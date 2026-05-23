package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.RegistrationOptionsResponse;
import com.crosscert.passkey.credential.api.RegistrationResult;
import com.crosscert.passkey.credential.api.RegistrationVerifyRequest;
import com.crosscert.passkey.credential.domain.AttestationMode;
import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.metadata.MdsConfig.MdsTrustAnchorSourceHolder;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.repository.TenantWebauthnConfigRepository;
import com.crosscert.passkey.credential.service.RegistrationService;
import com.crosscert.passkey.credential.webauthn.Base64UrlCodec;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.integration.support.IntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import com.crosscert.passkey.integration.support.TestSupportConfig;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * End-to-end strict-mode registration integration tests against the real docker-compose Oracle
 * instance. Verifies that the Spring DI wiring (RegistrationService → MdsTrustAnchorSourceHolder →
 * MdsTrustAnchorSource → VPD-isolated DB) works correctly for the mdsStrict=true tenant path.
 *
 * <p>Option B scope (per task plan): packed-full happy + reject, packed-self reject, none happy +
 * reject (revoked AAGUID) — covering the critical wiring paths without over-specifying.
 *
 * <p>MDS fixture strategy: A {@link FixtureMdsConfig} inner {@code @TestConfiguration} provides a
 * {@code MdsTrustAnchorSourceHolder} bean directly — bypassing {@code MdsBlobProvider} (which
 * requires an HTTP endpoint). The fixture builder generates in-memory root CA + leaf cert keypairs;
 * {@code passkey.mds.enabled} stays false so no real {@code MdsBlobProvider} bean is created, but
 * the {@code MdsTrustAnchorSourceHolder} is present so {@code RegistrationService} can use it.
 */
@Import({TestSupportConfig.class, RegistrationStrictIntegrationTest.FixtureMdsConfig.class})
class RegistrationStrictIntegrationTest extends IntegrationTestBase {

  // Shared fixture built once per test class.
  static MdsBlobFixtureBuilder FIXTURE;
  static MdsTrustAnchorSource TRUST_ANCHORS;

  @BeforeAll
  static void buildFixture() throws Exception {
    FIXTURE = MdsBlobFixtureBuilder.build();
    TRUST_ANCHORS = FIXTURE.toTrustAnchorSource();
  }

  // ---- Spring beans ----
  @Autowired RegistrationService registrationService;
  @Autowired TenantSeed seed;
  @Autowired TenantWebauthnConfigRepository webauthnConfigRepo;
  @Autowired TenantAttestationPolicyRepository policyRepo;
  @Autowired TransactionTemplate tx;

  // Per-test tenant state.
  UUID tenantId;

  // RP identity used in all tests — must match the rpIdHash in attestationObjects.
  static final String RP_ID = "strict-test.example.com";
  static final String RP_ORIGIN = "https://strict-test.example.com";

  @BeforeEach
  void setUpTenant() {
    tenantId = seed.createTenant("strict-" + UUID.randomUUID().toString().substring(0, 8));

    // Create WebAuthn config for the tenant.
    seed.withTenant(
        tenantId,
        () ->
            tx.executeWithoutResult(
                s -> {
                  TenantWebauthnConfig cfg =
                      TenantWebauthnConfig.create(
                          tenantId, RP_ID, "Strict Test", List.of(RP_ORIGIN));
                  webauthnConfigRepo.save(cfg);
                }));

    // Create a strict attestation policy (mdsStrict=true, mode=ANY, allowZeroAaguid=false).
    seed.withTenant(
        tenantId,
        () ->
            tx.executeWithoutResult(
                s -> {
                  TenantAttestationPolicy policy = TenantAttestationPolicy.permissive(tenantId);
                  // mdsStrict=true, allowZeroAaguid=false, allowSyncable=true
                  policy.update(AttestationMode.ANY, List.of(), List.of(), true, false, true);
                  policyRepo.save(policy);
                }));
  }

  @AfterEach
  void clearTenantContext() {
    TenantContextHolder.clear();
  }

  // ========================================================================================
  // Test 1: packed full-attestation — happy path (AAGUID in MDS, cert chain validates).
  // ========================================================================================

  @Test
  void packed_full_strict_passes_with_matching_trust_anchor() throws Exception {
    MdsBlobFixtureBuilder.AaguidFixture f =
        FIXTURE.scenarioFor(MdsBlobFixtureBuilder.PACKED_AAGUID);

    // Begin registration under tenant context.
    RegistrationOptionsResponse options = beginUnderTenant("user-packed-full-ok", "Packed User");

    // Build clientDataJSON + sha256 for the attestation signature.
    byte[] clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);
    byte[] clientDataHash = sha256(clientDataJson);

    // Build packed full attestationObject (leaf cert issued by fixture root CA).
    byte[] attObj = f.buildPackedFullAttestationObject(clientDataHash, RP_ID);

    // Finish registration.
    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            options.ceremonyId(),
            "cred-packed-full-ok",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObj),
            null,
            null);
    RegistrationResult result = finishUnderTenant(req);

    assertThat(result).isNotNull();
    assertThat(result.credentialId()).isNotBlank();
  }

  // ========================================================================================
  // Test 2: packed full-attestation — reject when AAGUID not in MDS.
  // ========================================================================================

  @Test
  void packed_full_strict_rejected_when_aaguid_not_in_mds() throws Exception {
    // Use a UUID that was NOT registered in the fixture's trust anchor source.
    UUID unknownAaguid = UUID.fromString("99999999-9999-9999-9999-999999999999");

    // Build a packed full attestation for the unknown AAGUID using an ad-hoc root+leaf.
    byte[] attObj;
    byte[] clientDataJson;
    UUID ceremonyId;
    {
      RegistrationOptionsResponse options =
          beginUnderTenant("user-packed-full-unknown-aaguid", "Unknown AAGUID User");
      clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);
      byte[] clientDataHash = sha256(clientDataJson);
      ceremonyId = options.ceremonyId();

      // Build a standalone attestation cert+root for the unknown AAGUID (not in the fixture MDS).
      java.security.KeyPairGenerator ecGen = java.security.KeyPairGenerator.getInstance("EC");
      ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
      java.security.KeyPair unknownRoot = ecGen.generateKeyPair();
      java.security.KeyPair unknownLeaf = ecGen.generateKeyPair();
      java.security.cert.X509Certificate unknownLeafCert =
          MdsBlobFixtureBuilder.issued(
              unknownLeaf,
              MdsBlobFixtureBuilder.ATT_OU_DN,
              unknownRoot,
              "CN=Unknown Root, O=Test, C=US",
              false,
              unknownAaguid);

      byte[] aaguidBytes = MdsBlobFixtureBuilder.uuidToBytes(unknownAaguid);
      byte[] rpIdHash = sha256(RP_ID.getBytes(StandardCharsets.UTF_8));
      java.security.KeyPair credPair = ecGen.generateKeyPair();
      byte[] coseKey =
          MdsBlobFixtureBuilder.ecCoseKey(
              (java.security.interfaces.ECPublicKey) credPair.getPublic());
      byte[] authData = buildAuthData(rpIdHash, aaguidBytes, coseKey);

      java.io.ByteArrayOutputStream signed = new java.io.ByteArrayOutputStream();
      signed.writeBytes(authData);
      signed.writeBytes(clientDataHash);
      java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
      sig.initSign(unknownLeaf.getPrivate());
      sig.update(signed.toByteArray());
      byte[] signature = sig.sign();

      java.util.Map<Object, Object> attStmt = new java.util.LinkedHashMap<>();
      attStmt.put("alg", -7L);
      attStmt.put("sig", signature);
      attStmt.put("x5c", List.of(unknownLeafCert.getEncoded()));
      java.util.Map<Object, Object> ao = new java.util.LinkedHashMap<>();
      ao.put("fmt", "packed");
      ao.put("attStmt", attStmt);
      ao.put("authData", authData);
      attObj = MdsBlobFixtureBuilder.cborEncodeMap(ao);
    }

    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            ceremonyId,
            "cred-packed-full-unknown",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObj),
            null,
            null);

    assertThatThrownBy(() -> finishUnderTenant(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.MDS_TRUST_FAILED);
  }

  // ========================================================================================
  // Test 3: packed self-attestation — reject when AAGUID not in MDS (strict self path).
  // ========================================================================================

  @Test
  void packed_self_strict_rejected_when_aaguid_not_in_mds() throws Exception {
    // Build a self-attestation with an AAGUID not registered in the fixture MDS.
    UUID unknownAaguid = UUID.fromString("88888888-8888-8888-8888-888888888888");

    RegistrationOptionsResponse options =
        beginUnderTenant("user-packed-self-unknown", "Self Attestation Unknown");
    byte[] clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);
    byte[] clientDataHash = sha256(clientDataJson);

    // Create a minimal AaguidFixture for the unknown AAGUID to use its
    // buildPackedSelfAttestationObject.
    java.security.KeyPairGenerator ecGen = java.security.KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.KeyPair credPair = ecGen.generateKeyPair();
    byte[] aaguidBytes = MdsBlobFixtureBuilder.uuidToBytes(unknownAaguid);
    byte[] rpIdHash = sha256(RP_ID.getBytes(StandardCharsets.UTF_8));
    byte[] coseKey =
        MdsBlobFixtureBuilder.ecCoseKey(
            (java.security.interfaces.ECPublicKey) credPair.getPublic());
    byte[] authData = buildAuthData(rpIdHash, aaguidBytes, coseKey);

    java.io.ByteArrayOutputStream signed = new java.io.ByteArrayOutputStream();
    signed.writeBytes(authData);
    signed.writeBytes(clientDataHash);
    java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
    sig.initSign(credPair.getPrivate());
    sig.update(signed.toByteArray());
    byte[] signature = sig.sign();

    java.util.Map<Object, Object> attStmt = new java.util.LinkedHashMap<>();
    attStmt.put("alg", -7L);
    attStmt.put("sig", signature);
    java.util.Map<Object, Object> ao = new java.util.LinkedHashMap<>();
    ao.put("fmt", "packed");
    ao.put("attStmt", attStmt);
    ao.put("authData", authData);
    byte[] attObj = MdsBlobFixtureBuilder.cborEncodeMap(ao);

    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            options.ceremonyId(),
            "cred-packed-self-unknown",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObj),
            null,
            null);

    assertThatThrownBy(() -> finishUnderTenant(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.MDS_TRUST_FAILED);
  }

  // ========================================================================================
  // Test 4: revoked AAGUID — packed full-attestation rejected with AUTHENTICATOR_REVOKED.
  // ========================================================================================

  @Test
  void packed_full_strict_rejected_when_aaguid_revoked() throws Exception {
    MdsBlobFixtureBuilder.AaguidFixture f =
        FIXTURE.scenarioFor(MdsBlobFixtureBuilder.REVOKED_AAGUID);

    RegistrationOptionsResponse options = beginUnderTenant("user-revoked", "Revoked User");
    byte[] clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);
    byte[] clientDataHash = sha256(clientDataJson);
    byte[] attObj = f.buildPackedFullAttestationObject(clientDataHash, RP_ID);

    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            options.ceremonyId(),
            "cred-revoked",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObj),
            null,
            null);

    assertThatThrownBy(() -> finishUnderTenant(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.AUTHENTICATOR_REVOKED);
  }

  // ========================================================================================
  // Test 5: none attestation — passes in strict tenant (fmt=none has no trust anchor check).
  // ========================================================================================

  @Test
  void none_attestation_passes_in_strict_tenant() throws Exception {
    RegistrationOptionsResponse options =
        beginUnderTenant("user-none-strict", "None Attestation User");
    byte[] clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);

    // Use a fixture-registered AAGUID so we exercise the strict-tenant + none-fmt bypass —
    // NoneAttestationVerifier does not consult MDS.
    byte[] rpIdHash = sha256(RP_ID.getBytes(StandardCharsets.UTF_8));
    byte[] packedAaguidBytes =
        MdsBlobFixtureBuilder.uuidToBytes(MdsBlobFixtureBuilder.PACKED_AAGUID);

    java.security.KeyPairGenerator ecGen = java.security.KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.KeyPair credPair = ecGen.generateKeyPair();
    byte[] coseKey =
        MdsBlobFixtureBuilder.ecCoseKey(
            (java.security.interfaces.ECPublicKey) credPair.getPublic());
    byte[] authDataWithAaguid = buildAuthData(rpIdHash, packedAaguidBytes, coseKey);

    java.util.Map<Object, Object> attStmt = new java.util.LinkedHashMap<>();
    java.util.Map<Object, Object> ao = new java.util.LinkedHashMap<>();
    ao.put("fmt", "none");
    ao.put("attStmt", attStmt);
    ao.put("authData", authDataWithAaguid);
    byte[] attObjWithAaguid = MdsBlobFixtureBuilder.cborEncodeMap(ao);

    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            options.ceremonyId(),
            "cred-none-strict",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObjWithAaguid),
            null,
            null);

    RegistrationResult result = finishUnderTenant(req);
    assertThat(result).isNotNull();
    assertThat(result.credentialId()).isNotBlank();
  }

  // ========================================================================================
  // Test 6: packed full — reject when zero AAGUID (MDS allows it, policy blocks it).
  // ========================================================================================

  @Test
  void packed_full_strict_rejected_when_zero_aaguid_and_policy_disallows() throws Exception {
    // ZERO_AAGUID is registered in the fixture MDS as FIDO_CERTIFIED so that the MDS trust check
    // passes, and the policy layer (allowZeroAaguid=false) is actually reached and fires.
    // This verifies that AAGUID_NOT_ALLOWED is returned — not MDS_TRUST_FAILED.
    MdsBlobFixtureBuilder.AaguidFixture f = FIXTURE.scenarioFor(MdsBlobFixtureBuilder.ZERO_AAGUID);

    RegistrationOptionsResponse options = beginUnderTenant("user-zero-aaguid", "Zero AAGUID User");
    byte[] clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);
    byte[] clientDataHash = sha256(clientDataJson);
    byte[] attObj = f.buildPackedFullAttestationObject(clientDataHash, RP_ID);

    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            options.ceremonyId(),
            "cred-zero-aaguid",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObj),
            null,
            null);

    assertThatThrownBy(() -> finishUnderTenant(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.AAGUID_NOT_ALLOWED);
  }

  // ========================================================================================
  // Test 7: tenant isolation — strict tenant A sees only its policy, not tenant B's.
  // ========================================================================================

  @Test
  void mds_strict_is_tenant_isolated() throws Exception {
    // Create a second tenant (non-strict).
    UUID tenantBId = seed.createTenant("strict-b-" + UUID.randomUUID().toString().substring(0, 8));
    seed.withTenant(
        tenantBId,
        () ->
            tx.executeWithoutResult(
                s -> {
                  TenantWebauthnConfig cfg =
                      TenantWebauthnConfig.create(
                          tenantBId, RP_ID, "Non-Strict Test", List.of(RP_ORIGIN));
                  webauthnConfigRepo.save(cfg);
                  // Non-strict policy for tenant B.
                  policyRepo.save(TenantAttestationPolicy.permissive(tenantBId));
                }));

    // Tenant A (strict) — registration with unknown AAGUID must fail.
    UUID unknownAaguid = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    RegistrationOptionsResponse optionsA = beginUnderTenant("user-a-isolation", "User A");
    byte[] clientDataJsonA = buildClientDataJson(optionsA.challenge(), RP_ORIGIN);
    byte[] clientDataHashA = sha256(clientDataJsonA);
    java.security.KeyPairGenerator ecGen = java.security.KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.KeyPair credPairA = ecGen.generateKeyPair();
    byte[] coseKeyA =
        MdsBlobFixtureBuilder.ecCoseKey(
            (java.security.interfaces.ECPublicKey) credPairA.getPublic());
    byte[] authDataA =
        buildAuthData(
            sha256(RP_ID.getBytes(StandardCharsets.UTF_8)),
            MdsBlobFixtureBuilder.uuidToBytes(unknownAaguid),
            coseKeyA);
    java.io.ByteArrayOutputStream signedA = new java.io.ByteArrayOutputStream();
    signedA.writeBytes(authDataA);
    signedA.writeBytes(clientDataHashA);
    java.security.Signature sigA = java.security.Signature.getInstance("SHA256withECDSA");
    sigA.initSign(credPairA.getPrivate());
    sigA.update(signedA.toByteArray());
    byte[] signatureA = sigA.sign();
    java.util.Map<Object, Object> attStmtA = new java.util.LinkedHashMap<>();
    attStmtA.put("alg", -7L);
    attStmtA.put("sig", signatureA);
    java.util.Map<Object, Object> aoA = new java.util.LinkedHashMap<>();
    aoA.put("fmt", "packed");
    aoA.put("attStmt", attStmtA);
    aoA.put("authData", authDataA);
    byte[] attObjA = MdsBlobFixtureBuilder.cborEncodeMap(aoA);

    RegistrationVerifyRequest reqA =
        new RegistrationVerifyRequest(
            optionsA.ceremonyId(),
            "cred-a-isolation",
            Base64UrlCodec.encode(clientDataJsonA),
            Base64UrlCodec.encode(attObjA),
            null,
            null);
    // Tenant A (strict) must reject unknown AAGUID.
    assertThatThrownBy(() -> finishUnderTenant(reqA))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.MDS_TRUST_FAILED);

    // Tenant B (non-strict) — same unknown AAGUID (zero used for none attestation) must pass.
    // Use none format (no MDS check) + a real AAGUID that's in the fixture to avoid zero-AAGUID
    // block. Actually use packed-self with the unknown AAGUID — non-strict has no MDS trust check.
    RegistrationOptionsResponse optionsB =
        seed.withTenant(
            tenantBId,
            () ->
                tx.execute(
                    s -> registrationService.beginRegistration("user-b-isolation", "User B")));

    byte[] clientDataJsonB = buildClientDataJson(optionsB.challenge(), RP_ORIGIN);
    byte[] clientDataHashB = sha256(clientDataJsonB);
    java.security.KeyPair credPairB = ecGen.generateKeyPair();
    byte[] coseKeyB =
        MdsBlobFixtureBuilder.ecCoseKey(
            (java.security.interfaces.ECPublicKey) credPairB.getPublic());
    // Use a non-zero AAGUID so permissive policy's allowZeroAaguid=false doesn't block it.
    // Permissive policy from permissive() has allowZeroAaguid=false — use a real AAGUID.
    byte[] aaguidBytesB = MdsBlobFixtureBuilder.uuidToBytes(unknownAaguid);
    byte[] authDataB =
        buildAuthData(sha256(RP_ID.getBytes(StandardCharsets.UTF_8)), aaguidBytesB, coseKeyB);
    java.io.ByteArrayOutputStream signedB = new java.io.ByteArrayOutputStream();
    signedB.writeBytes(authDataB);
    signedB.writeBytes(clientDataHashB);
    java.security.Signature sigB = java.security.Signature.getInstance("SHA256withECDSA");
    sigB.initSign(credPairB.getPrivate());
    sigB.update(signedB.toByteArray());
    byte[] signatureB = sigB.sign();
    java.util.Map<Object, Object> attStmtB = new java.util.LinkedHashMap<>();
    attStmtB.put("alg", -7L);
    attStmtB.put("sig", signatureB);
    java.util.Map<Object, Object> aoB = new java.util.LinkedHashMap<>();
    aoB.put("fmt", "packed");
    aoB.put("attStmt", attStmtB);
    aoB.put("authData", authDataB);
    byte[] attObjB = MdsBlobFixtureBuilder.cborEncodeMap(aoB);

    RegistrationVerifyRequest reqB =
        new RegistrationVerifyRequest(
            optionsB.ceremonyId(),
            "cred-b-isolation",
            Base64UrlCodec.encode(clientDataJsonB),
            Base64UrlCodec.encode(attObjB),
            null,
            null);
    RegistrationResult resultB =
        seed.withTenant(
            tenantBId, () -> tx.execute(s -> registrationService.finishRegistration(reqB)));
    assertThat(resultB).isNotNull();
    assertThat(resultB.credentialId()).isNotBlank();
  }

  // ========================================================================================
  // Test 8: MDS unavailable — strict tenant fails with MDS_UNAVAILABLE when holder is null.
  //         (This test uses a non-strict tenant instead, verifying that non-strict bypasses MDS.)
  // ========================================================================================

  @Test
  void non_strict_tenant_does_not_require_mds_holder() throws Exception {
    // Create a non-strict tenant.
    UUID nonStrictTenantId =
        seed.createTenant("non-strict-" + UUID.randomUUID().toString().substring(0, 8));
    seed.withTenant(
        nonStrictTenantId,
        () ->
            tx.executeWithoutResult(
                s -> {
                  TenantWebauthnConfig cfg =
                      TenantWebauthnConfig.create(
                          nonStrictTenantId, RP_ID, "Non-Strict", List.of(RP_ORIGIN));
                  webauthnConfigRepo.save(cfg);
                  // Permissive policy — mdsStrict=false.
                  TenantAttestationPolicy policy =
                      TenantAttestationPolicy.permissive(nonStrictTenantId);
                  policy.update(AttestationMode.ANY, List.of(), List.of(), false, false, true);
                  policyRepo.save(policy);
                }));

    RegistrationOptionsResponse options =
        seed.withTenant(
            nonStrictTenantId,
            () ->
                tx.execute(
                    s ->
                        registrationService.beginRegistration(
                            "user-non-strict", "Non-strict User")));

    byte[] clientDataJson = buildClientDataJson(options.challenge(), RP_ORIGIN);
    byte[] clientDataHash = sha256(clientDataJson);

    // Use PACKED_AAGUID + packed-full from the fixture — non-strict, so MDS trust anchor lookup
    // is skipped entirely. The cert chain is NOT validated against the MDS root in non-strict mode.
    MdsBlobFixtureBuilder.AaguidFixture f =
        FIXTURE.scenarioFor(MdsBlobFixtureBuilder.PACKED_AAGUID);
    byte[] attObj = f.buildPackedFullAttestationObject(clientDataHash, RP_ID);

    RegistrationVerifyRequest req =
        new RegistrationVerifyRequest(
            options.ceremonyId(),
            "cred-non-strict",
            Base64UrlCodec.encode(clientDataJson),
            Base64UrlCodec.encode(attObj),
            null,
            null);

    RegistrationResult result =
        seed.withTenant(
            nonStrictTenantId, () -> tx.execute(s -> registrationService.finishRegistration(req)));
    assertThat(result).isNotNull();
    assertThat(result.credentialId()).isNotBlank();
  }

  // ========================================================================================
  // Helpers.
  // ========================================================================================

  private RegistrationOptionsResponse beginUnderTenant(String userId, String displayName) {
    return seed.withTenant(
        tenantId,
        () -> tx.execute(s -> registrationService.beginRegistration(userId, displayName)));
  }

  private RegistrationResult finishUnderTenant(RegistrationVerifyRequest req) {
    return seed.withTenant(
        tenantId, () -> tx.execute(s -> registrationService.finishRegistration(req)));
  }

  /** Builds a minimal clientDataJSON matching WebAuthn §5.8.1 format. */
  private static byte[] buildClientDataJson(String challengeB64u, String origin) {
    String json =
        "{\"type\":\"webauthn.create\",\"challenge\":\""
            + challengeB64u
            + "\",\"origin\":\""
            + origin
            + "\"}";
    return json.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Builds authenticator data: rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) |
   * credId(4) | coseKey.
   */
  private static byte[] buildAuthData(byte[] rpIdHash, byte[] aaguidBytes, byte[] coseKey) {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    out.writeBytes(rpIdHash);
    out.write(0x45); // UP | UV | AT
    out.writeBytes(new byte[] {0, 0, 0, 0}); // signCount = 0
    out.writeBytes(aaguidBytes); // 16-byte AAGUID
    out.writeBytes(new byte[] {0, 4}); // credIdLen = 4
    out.writeBytes(new byte[] {1, 2, 3, 4}); // credId
    out.writeBytes(coseKey);
    return out.toByteArray();
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return java.security.MessageDigest.getInstance("SHA-256").digest(data);
  }

  // ========================================================================================
  // TestConfiguration: inject MdsTrustAnchorSourceHolder directly (bypasses MdsBlobProvider).
  // ========================================================================================

  /**
   * Provides a {@link MdsTrustAnchorSourceHolder} backed by the in-memory {@link
   * MdsBlobFixtureBuilder} trust anchor source, bypassing the real {@link
   * com.crosscert.passkey.credential.metadata.MdsBlobProvider} (which needs an HTTP endpoint and is
   * disabled by {@code passkey.mds.enabled=false} in the test profile).
   *
   * <p>The {@code @Primary} annotation ensures this bean wins over any conditionally-wired
   * production holder if one were somehow present.
   */
  @TestConfiguration
  static class FixtureMdsConfig {

    @Bean
    @Primary
    public MdsTrustAnchorSourceHolder fixtureMdsTrustAnchorSourceHolder() {
      // TRUST_ANCHORS is set in @BeforeAll; Spring context initializes after @BeforeAll.
      // We return a holder that lazily reads the static field.
      return () -> TRUST_ANCHORS;
    }
  }
}
