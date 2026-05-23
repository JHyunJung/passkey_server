package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.AttestationVerifiers;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class AttestationVerifierTest {

  /** The FIDO AAGUID certificate extension OID (WebAuthn L3 §8.2.1). */
  private static final String FIDO_AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4";

  @Test
  void verifies_none_attestation() throws Exception {
    AttestationObject obj = AttestationObject.parse(noneAttestationObject());
    AttestationResult result =
        AttestationVerifiers.forFormat("none").verify(obj, new byte[32], null);
    assertThat(result.format()).isEqualTo("none");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void none_attestation_with_non_empty_statement_is_rejected() {
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("x", 1L);
    AttestationObject obj = AttestationObject.parse(attestationObject("none", attStmt));
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("none").verify(obj, new byte[32], null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void unsupported_format_is_rejected() {
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("tpm"))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UNSUPPORTED_ATTESTATION_FORMAT);
  }

  @Test
  void verifies_packed_self_attestation() throws Exception {
    byte[] clientDataHash = new byte[32];
    AttestationObject obj =
        AttestationObject.parse(packedSelfAttestationObject(clientDataHash, true));
    AttestationResult result =
        AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null);
    assertThat(result.format()).isEqualTo("packed");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void packed_with_invalid_signature_is_rejected() throws Exception {
    byte[] clientDataHash = new byte[32];
    AttestationObject obj =
        AttestationObject.parse(packedSelfAttestationObject(clientDataHash, false));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void verifies_packed_full_attestation_with_es256_x5c() throws Exception {
    // ES256 x5c full attestation: a §8.2.1-compliant attestation cert signs authData||clientHash.
    byte[] clientDataHash = new byte[32];
    byte[] aaguid = new byte[16];

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert = attestationCert(attPair, "SHA256withECDSA", REQUIRED_OU_DN, aaguid);

    byte[] authDataBytes = authData(aaguid, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withECDSA", authDataBytes, clientDataHash);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, sig, attCert));
    AttestationResult result =
        AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null);
    assertThat(result.format()).isEqualTo("packed");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void verifies_packed_full_attestation_with_rs256_x5c() throws Exception {
    // RS256 x5c full attestation: exercises the SHA256withRSA verification path.
    byte[] clientDataHash = new byte[32];
    byte[] aaguid = new byte[16];

    KeyPair attPair = rsaKeyPair();
    X509Certificate attCert = attestationCert(attPair, "SHA256withRSA", REQUIRED_OU_DN, aaguid);

    byte[] authDataBytes = authData(aaguid, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withRSA", authDataBytes, clientDataHash);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -257L, sig, attCert));
    AttestationResult result =
        AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null);
    assertThat(result.format()).isEqualTo("packed");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void packed_x5c_with_invalid_signature_is_rejected() throws Exception {
    // §8.2.1-compliant cert but a garbage signature — must be rejected.
    byte[] clientDataHash = new byte[32];
    byte[] aaguid = new byte[16];

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert = attestationCert(attPair, "SHA256withECDSA", REQUIRED_OU_DN, aaguid);

    byte[] authDataBytes = authData(aaguid, ecCoseKey(ecKeyPair()));
    byte[] badSig = "notasignature".getBytes(StandardCharsets.UTF_8);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, badSig, attCert));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_x5c_cert_without_required_ou_is_rejected() throws Exception {
    // §8.2.1: subject OU must be exactly "Authenticator Attestation" — this cert has no OU.
    byte[] clientDataHash = new byte[32];
    byte[] aaguid = new byte[16];

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert =
        attestationCert(attPair, "SHA256withECDSA", "CN=No OU Here, O=Test, C=US", aaguid);

    byte[] authDataBytes = authData(aaguid, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withECDSA", authDataBytes, clientDataHash);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, sig, attCert));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_x5c_cert_with_wrong_ou_is_rejected() throws Exception {
    // §8.2.1: subject OU present but wrong value — must be rejected.
    byte[] clientDataHash = new byte[32];
    byte[] aaguid = new byte[16];

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert =
        attestationCert(
            attPair, "SHA256withECDSA", "CN=Test, OU=Something Else, O=Test, C=US", aaguid);

    byte[] authDataBytes = authData(aaguid, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withECDSA", authDataBytes, clientDataHash);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, sig, attCert));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_x5c_cert_with_ca_true_is_rejected() throws Exception {
    // §8.2.1: Basic Constraints CA component must be false — this cert is a CA.
    byte[] clientDataHash = new byte[32];
    byte[] aaguid = new byte[16];

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert = caAttestationCert(attPair, "SHA256withECDSA", REQUIRED_OU_DN);

    byte[] authDataBytes = authData(aaguid, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withECDSA", authDataBytes, clientDataHash);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, sig, attCert));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_x5c_cert_with_mismatched_aaguid_extension_is_rejected() throws Exception {
    // §8.2.1: the FIDO AAGUID extension, when present, must match the authData AAGUID.
    byte[] clientDataHash = new byte[32];
    byte[] authDataAaguid = new byte[16]; // all-zeros in authData
    byte[] certAaguid = new byte[16];
    certAaguid[0] = 0x42; // different value in the cert extension

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert =
        attestationCert(attPair, "SHA256withECDSA", REQUIRED_OU_DN, certAaguid);

    byte[] authDataBytes = authData(authDataAaguid, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withECDSA", authDataBytes, clientDataHash);

    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, sig, attCert));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_missing_sig_is_rejected() throws Exception {
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -7L);
    AttestationObject obj = AttestationObject.parse(attestationObject("packed", attStmt));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(obj, new byte[32], null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_with_alg_mismatch_is_rejected() throws Exception {
    // attStmt.alg를 credential 키의 alg(-7)와 다른 값(-257)으로 — §8.2 alg 일치 검증 위반.
    byte[] clientDataHash = new byte[32];
    AttestationObject base =
        AttestationObject.parse(packedSelfAttestationObject(clientDataHash, true));
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -257L);
    attStmt.put("sig", (byte[]) base.attestationStatement().get("sig"));
    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", base.authenticatorData().rawBytes());
    AttestationObject mismatched = AttestationObject.parse(CborTestEncoder.encodeMap(obj));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(mismatched, clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  // ---------------------------------------------------------------------------------------------
  // Strict-mode (MdsTrustAnchorSource != null) packed full attestation tests.
  // ---------------------------------------------------------------------------------------------

  @Test
  void strict_packed_full_passes_with_trusted_chain() throws Exception {
    StrictPackedScenario s = strictPackedScenario(false /* not revoked */);
    AttestationResult result =
        AttestationVerifiers.forFormat("packed")
            .verify(s.attestationObject(), s.clientDataHash(), s.trustAnchors());
    assertThat(result.format()).isEqualTo("packed");
    assertThat(result.trustPathPresent()).isTrue();
  }

  @Test
  void strict_packed_full_rejects_unknown_aaguid() throws Exception {
    // trustAnchors with NO entry for the credential's AAGUID — MDS_TRUST_FAILED.
    StrictPackedScenario s = strictPackedScenario(false);
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource empty =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of());
    assertThatThrownBy(
            () ->
                AttestationVerifiers.forFormat("packed")
                    .verify(s.attestationObject(), s.clientDataHash(), empty))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.MDS_TRUST_FAILED);
  }

  @Test
  void strict_packed_full_rejects_revoked_authenticator() throws Exception {
    StrictPackedScenario s = strictPackedScenario(true /* revoked */);
    assertThatThrownBy(
            () ->
                AttestationVerifiers.forFormat("packed")
                    .verify(s.attestationObject(), s.clientDataHash(), s.trustAnchors()))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.AUTHENTICATOR_REVOKED);
  }

  @Test
  void strict_packed_full_rejects_untrusted_chain() throws Exception {
    // The MDS entry exists for the AAGUID but registers a DIFFERENT root CA as trust anchor.
    StrictPackedScenario s = strictPackedScenario(false);
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource wrongAnchor =
        strictScenarioWithWrongRoot(s.aaguid());
    assertThatThrownBy(
            () ->
                AttestationVerifiers.forFormat("packed")
                    .verify(s.attestationObject(), s.clientDataHash(), wrongAnchor))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.TRUST_PATH_INVALID);
  }

  // ---------------------------------------------------------------------------------------------
  // Strict-mode scenario fixtures.
  // ---------------------------------------------------------------------------------------------

  /**
   * A strict-mode packed full attestation test scenario: an attestation certificate satisfying
   * §8.2.1 (X.509 v3, CA=false, OU="Authenticator Attestation") issued by a root CA, the
   * attestationObject signed by that cert's key, and an MdsTrustAnchorSource registering the root
   * CA for the credential's AAGUID.
   */
  private record StrictPackedScenario(
      AttestationObject attestationObject,
      byte[] clientDataHash,
      com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource trustAnchors,
      java.util.UUID aaguid) {}

  /**
   * Builds a strict-mode scenario. The attestation cert (§8.2.1-compliant) is issued by a root CA;
   * the x5c chain carries only that leaf cert and the root CA is the MDS trust anchor — matching
   * {@link com.crosscert.passkey.fido2.attestation.AttestationCertPathValidator}'s leaf-first,
   * anchor-excluded chain contract. When {@code revoked} is true the MDS entry's status report is
   * {@code REVOKED}.
   */
  private static StrictPackedScenario strictPackedScenario(boolean revoked) throws Exception {
    byte[] clientDataHash = new byte[32];
    byte[] aaguidBytes = fixedAaguid();
    java.util.UUID aaguid = uuidOf(aaguidBytes);

    KeyPair rootPair = ecKeyPair();
    X509Certificate rootCa = issuedCert(rootPair, ROOT_CA_DN, rootPair, ROOT_CA_DN, true, null);

    KeyPair attPair = ecKeyPair();
    X509Certificate attCert =
        issuedCert(attPair, REQUIRED_OU_DN, rootPair, ROOT_CA_DN, false, aaguidBytes);

    byte[] authDataBytes = authData(aaguidBytes, ecCoseKey(ecKeyPair()));
    byte[] sig = sign(attPair.getPrivate(), "SHA256withECDSA", authDataBytes, clientDataHash);
    AttestationObject obj =
        AttestationObject.parse(packedFullAttestation(authDataBytes, -7L, sig, attCert));

    com.crosscert.passkey.fido2.mds.StatusReport status =
        revoked
            ? com.crosscert.passkey.fido2.mds.StatusReport.REVOKED
            : com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED;
    com.crosscert.passkey.fido2.mds.MetadataEntry entry =
        new com.crosscert.passkey.fido2.mds.MetadataEntry(
            aaguid, java.util.List.of(rootCa), java.util.List.of(status));
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource trustAnchors =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of(entry));

    return new StrictPackedScenario(obj, clientDataHash, trustAnchors, aaguid);
  }

  /**
   * An {@code MdsTrustAnchorSource} that has an entry for {@code aaguid} (so MDS lookup succeeds
   * and the authenticator is non-revoked) but registers an unrelated root CA as the trust anchor —
   * the attestation cert does not chain to it, so PKIX path validation fails.
   */
  private static com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource strictScenarioWithWrongRoot(
      java.util.UUID aaguid) throws Exception {
    KeyPair wrongRootPair = ecKeyPair();
    X509Certificate wrongRoot =
        issuedCert(wrongRootPair, ROOT_CA_DN, wrongRootPair, ROOT_CA_DN, true, null);
    com.crosscert.passkey.fido2.mds.MetadataEntry entry =
        new com.crosscert.passkey.fido2.mds.MetadataEntry(
            aaguid,
            java.util.List.of(wrongRoot),
            java.util.List.of(com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED));
    return new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of(entry));
  }

  /** A subject DN for a root CA — distinct from the §8.2.1 attestation-cert OU DN. */
  private static final String ROOT_CA_DN = "CN=Test Attestation Root CA, O=Test, C=US";

  /** A fixed 16-byte AAGUID for strict-mode scenarios (non-zero so it is unambiguous). */
  private static byte[] fixedAaguid() {
    byte[] aaguid = new byte[16];
    for (int i = 0; i < 16; i++) {
      aaguid[i] = (byte) (0xA0 + i);
    }
    return aaguid;
  }

  /** Decodes 16 AAGUID bytes into a {@link java.util.UUID}. */
  private static java.util.UUID uuidOf(byte[] aaguid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(aaguid);
    return new java.util.UUID(buf.getLong(), buf.getLong());
  }

  /**
   * Builds an X.509 v3 certificate for {@code subjectPair} issued (signed) by {@code issuerPair}.
   * Self-signed when issuer == subject. Adds Basic Constraints ({@code ca}) and — when {@code
   * aaguid} is non-null — the FIDO AAGUID extension. Reuses the same BouncyCastle builder pattern
   * as {@link #buildCert}, parameterized on the issuer so a root CA can sign an attestation cert.
   */
  private static X509Certificate issuedCert(
      KeyPair subjectPair,
      String subjectDn,
      KeyPair issuerPair,
      String issuerDn,
      boolean ca,
      byte[] aaguid)
      throws Exception {
    Instant now = Instant.now();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn),
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            new X500Name(subjectDn),
            subjectPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
    if (aaguid != null) {
      builder.addExtension(
          new ASN1ObjectIdentifier(FIDO_AAGUID_EXTENSION_OID), false, new DEROctetString(aaguid));
    }
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA").build(issuerPair.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  // ---------------------------------------------------------------------------------------------
  // Fixture helpers.
  // ---------------------------------------------------------------------------------------------

  /** A §8.2.1-compliant subject DN: subject OU is exactly "Authenticator Attestation". */
  private static final String REQUIRED_OU_DN =
      "CN=Test Attestation, OU=Authenticator Attestation, O=Test, C=US";

  private static byte[] noneAttestationObject() {
    return attestationObject("none", new LinkedHashMap<>());
  }

  private static byte[] attestationObject(String fmt, Map<Object, Object> attStmt) {
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(new byte[32]);
    authData.write(0x41); // UP | AT
    authData.writeBytes(new byte[] {0, 0, 0, 0});
    authData.writeBytes(new byte[16]); // aaguid
    authData.writeBytes(new byte[] {0, 2}); // credIdLen
    authData.writeBytes(new byte[] {1, 2}); // credId
    authData.writeBytes(sampleCoseKey());

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", fmt);
    obj.put("attStmt", attStmt);
    obj.put("authData", authData.toByteArray());
    return CborTestEncoder.encodeMap(obj);
  }

  /**
   * Builds a packed self-attestation attestationObject. The authData embeds the credential's COSE
   * public key, and attStmt.sig is a real ES256 signature over authData || clientDataHash by the
   * matching private key — a self-consistent fixture.
   */
  private static byte[] packedSelfAttestationObject(byte[] clientDataHash, boolean validSig)
      throws Exception {
    KeyPair pair = ecKeyPair();
    byte[] authDataBytes = authData(new byte[16], ecCoseKey(pair));

    ByteArrayOutputStream signed = new ByteArrayOutputStream();
    signed.writeBytes(authDataBytes);
    signed.writeBytes(clientDataHash);
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(pair.getPrivate());
    signer.update(validSig ? signed.toByteArray() : "garbage".getBytes(StandardCharsets.UTF_8));
    byte[] sig = signer.sign();

    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -7L);
    attStmt.put("sig", sig);

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", authDataBytes);
    return CborTestEncoder.encodeMap(obj);
  }

  /** Assembles a packed full-attestation (x5c) attestationObject CBOR blob. */
  private static byte[] packedFullAttestation(
      byte[] authDataBytes, long alg, byte[] sig, X509Certificate cert) throws Exception {
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", alg);
    attStmt.put("sig", sig);
    attStmt.put("x5c", List.of(cert.getEncoded()));

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", authDataBytes);
    return CborTestEncoder.encodeMap(obj);
  }

  /** Builds authenticator data with the given AAGUID and embedded COSE credential key. */
  private static byte[] authData(byte[] aaguid, byte[] coseKey) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(new byte[32]); // rpIdHash
    out.write(0x41); // UP | AT
    out.writeBytes(new byte[] {0, 0, 0, 0}); // signCount
    out.writeBytes(aaguid); // 16-byte AAGUID
    out.writeBytes(new byte[] {0, 2}); // credIdLen
    out.writeBytes(new byte[] {1, 2}); // credId
    out.writeBytes(coseKey);
    return out.toByteArray();
  }

  /** Signs {@code authData || clientDataHash} with the given key and JCA algorithm. */
  private static byte[] sign(
      PrivateKey privateKey, String jcaAlg, byte[] authData, byte[] clientDataHash)
      throws Exception {
    ByteArrayOutputStream signed = new ByteArrayOutputStream();
    signed.writeBytes(authData);
    signed.writeBytes(clientDataHash);
    Signature signer = Signature.getInstance(jcaAlg);
    signer.initSign(privateKey);
    signer.update(signed.toByteArray());
    return signer.sign();
  }

  private static KeyPair ecKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    return gen.generateKeyPair();
  }

  private static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    return gen.generateKeyPair();
  }

  /** Encodes an ES256 COSE_Key from an EC key pair's public key. */
  private static byte[] ecCoseKey(KeyPair pair) {
    ECPublicKey pub = (ECPublicKey) pair.getPublic();
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L);
    m.put(3L, -7L);
    m.put(-1L, 1L);
    m.put(-2L, coordinate(pub.getW().getAffineX()));
    m.put(-3L, coordinate(pub.getW().getAffineY()));
    return CborTestEncoder.encodeMap(m);
  }

  private static byte[] sampleCoseKey() {
    try {
      return ecCoseKey(ecKeyPair());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Builds a §8.2.1-compliant self-signed attestation certificate using BouncyCastle: X.509 v3,
   * Basic Constraints CA=false, the given subject DN, and a FIDO AAGUID extension carrying {@code
   * aaguid}.
   */
  private static X509Certificate attestationCert(
      KeyPair keyPair, String signingAlg, String dn, byte[] aaguid) throws Exception {
    return buildCert(keyPair, signingAlg, dn, false, aaguid);
  }

  /**
   * Builds a self-signed attestation certificate with Basic Constraints CA=true (§8.2.1 violation).
   */
  private static X509Certificate caAttestationCert(KeyPair keyPair, String signingAlg, String dn)
      throws Exception {
    return buildCert(keyPair, signingAlg, dn, true, null);
  }

  private static X509Certificate buildCert(
      KeyPair keyPair, String signingAlg, String dn, boolean ca, byte[] aaguid) throws Exception {
    X500Name subject = new X500Name(dn);
    PublicKey publicKey = keyPair.getPublic();
    Instant now = Instant.now();
    Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
    Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject, // self-signed: issuer == subject
            BigInteger.valueOf(System.nanoTime()),
            notBefore,
            notAfter,
            subject,
            publicKey);

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
    if (aaguid != null) {
      builder.addExtension(
          new ASN1ObjectIdentifier(FIDO_AAGUID_EXTENSION_OID), false, new DEROctetString(aaguid));
    }

    ContentSigner signer = new JcaContentSignerBuilder(signingAlg).build(keyPair.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  /** Pads/truncates a coordinate to the fixed 32-byte big-endian form COSE_Key expects. */
  private static byte[] coordinate(BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    if (raw.length > 32) {
      System.arraycopy(raw, raw.length - 32, out, 0, 32);
    } else {
      System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
    }
    return out;
  }
}
