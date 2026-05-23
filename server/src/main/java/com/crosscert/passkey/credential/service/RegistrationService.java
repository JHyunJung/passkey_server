package com.crosscert.passkey.credential.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.RegistrationOptionsResponse;
import com.crosscert.passkey.credential.api.RegistrationResult;
import com.crosscert.passkey.credential.api.RegistrationVerifyRequest;
import com.crosscert.passkey.credential.challenge.CeremonyType;
import com.crosscert.passkey.credential.challenge.ChallengeRecord;
import com.crosscert.passkey.credential.challenge.ChallengeStore;
import com.crosscert.passkey.credential.challenge.WebauthnCeremonyProperties;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.metadata.MdsConfig.MdsTrustAnchorSourceHolder;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.webauthn.Base64UrlCodec;
import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class RegistrationService {

  private static final SecureRandom RNG = new SecureRandom();

  // ES256 (-7), RS256 (-257).
  private static final long COSE_ALG_ES256 = -7;
  private static final long COSE_ALG_RS256 = -257;

  private final TenantWebauthnConfigService configService;
  private final TenantAttestationPolicyRepository policyRepo;
  private final TenantUserRepository userRepo;
  private final CredentialRepository credentialRepo;
  private final ChallengeStore challengeStore;
  private final ObjectProvider<MdsTrustAnchorSourceHolder> mdsHolderProvider;
  private final AuditService auditService;
  private final WebauthnCeremonyProperties ceremonyProps;
  private final com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics;

  public RegistrationService(
      TenantWebauthnConfigService configService,
      TenantAttestationPolicyRepository policyRepo,
      TenantUserRepository userRepo,
      CredentialRepository credentialRepo,
      ChallengeStore challengeStore,
      ObjectProvider<MdsTrustAnchorSourceHolder> mdsHolderProvider,
      AuditService auditService,
      WebauthnCeremonyProperties ceremonyProps,
      com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics) {
    this.configService = configService;
    this.policyRepo = policyRepo;
    this.userRepo = userRepo;
    this.credentialRepo = credentialRepo;
    this.challengeStore = challengeStore;
    this.mdsHolderProvider = mdsHolderProvider;
    this.auditService = auditService;
    this.ceremonyProps = ceremonyProps;
    this.metrics = metrics;
  }

  /**
   * Begins a WebAuthn registration ceremony for {@code externalUserId}. Resolves (or creates) the
   * {@code TenantUser}, stores a freshly generated challenge in Redis, and returns the options the
   * browser passes to {@code navigator.credentials.create()}. Caller must already hold the tenant
   * context (resolved by the API-key filter for RP traffic).
   */
  @Transactional
  public RegistrationOptionsResponse beginRegistration(String externalUserId, String displayName) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    TenantUser user = findOrCreateUser(externalUserId, displayName);

    byte[] challenge = randomBytes(ceremonyProps.challengeBytes());
    String challengeB64u = Base64UrlCodec.encode(challenge);
    // user.id (WebAuthn 5.4.3): UUID encoded as 16 raw bytes — base64url of the byte form, not
    // the dashed text form. The textual form is allowed by spec (length ≤ 64) but wastes 20 bytes
    // and breaks interop with RPs that expect the canonical raw encoding. Existing credentials in
    // the DB still carry the legacy 36-byte text encoding; user_handle has no server-side lookup
    // path so the two encodings can coexist until a backfill is scheduled.
    String userHandle = Base64UrlCodec.encode(uuidToBytes(user.getId()));

    ChallengeRecord record =
        new ChallengeRecord(
            challengeB64u, cfg.getTenantId(), user.getId(), CeremonyType.REGISTRATION, userHandle);
    UUID ceremonyId = challengeStore.save(record);

    // P2-3: emit start event so the funnel can measure begin → finish drop-off (synchronous so
    // that even ceremonies abandoned before finishRegistration leave a trail).
    auditService.append(
        AuditEventType.REGISTRATION_OPTIONS_REQUESTED,
        ActorType.END_USER,
        user.getId().toString(),
        "TENANT_USER",
        user.getId().toString(),
        java.util.Map.of("ceremonyId", ceremonyId.toString()));

    List<RegistrationOptionsResponse.ExcludeCredential> excludeCredentials =
        credentialRepo.findAllByTenantUserId(user.getId()).stream()
            .filter(Credential::isActive)
            .map(
                c ->
                    new RegistrationOptionsResponse.ExcludeCredential(
                        "public-key", c.getCredentialId(), c.getTransports()))
            .toList();

    log.info(
        "register.begin tenantId={} tenantUserId={} externalUserId={} ceremonyId={} "
            + "excludeCredentials={}",
        cfg.getTenantId(),
        user.getId(),
        externalUserId,
        ceremonyId,
        excludeCredentials.size());

    return new RegistrationOptionsResponse(
        ceremonyId,
        challengeB64u,
        new RegistrationOptionsResponse.Rp(cfg.getRpId(), cfg.getRpName()),
        new RegistrationOptionsResponse.User(userHandle, externalUserId, displayName),
        List.of(
            new RegistrationOptionsResponse.PubKeyCredParam("public-key", COSE_ALG_ES256),
            new RegistrationOptionsResponse.PubKeyCredParam("public-key", COSE_ALG_RS256)),
        cfg.getTimeoutMs(),
        cfg.getAttestationConveyance().name().toLowerCase(Locale.ROOT),
        new RegistrationOptionsResponse.AuthenticatorSelection(
            cfg.getUserVerification().name().toLowerCase(Locale.ROOT),
            cfg.getResidentKey().name().toLowerCase(Locale.ROOT),
            cfg.getResidentKey()
                == com.crosscert.passkey.credential.domain.ResidentKeyPolicy.REQUIRED),
        excludeCredentials,
        buildExtensions(cfg));
  }

  /**
   * Build the WebAuthn extension inputs map. Empty when no tenant policy requires any — Jackson
   * drops it from the JSON via {@code @JsonInclude(NON_EMPTY)} so legacy clients are unaffected.
   */
  private static java.util.Map<String, Object> buildExtensions(
      com.crosscert.passkey.credential.domain.TenantWebauthnConfig cfg) {
    java.util.Map<String, Object> ext = new java.util.HashMap<>();
    if (cfg.getCredProtect() != null
        && cfg.getCredProtect() != com.crosscert.passkey.credential.domain.CredProtectPolicy.NONE) {
      ext.put("credentialProtectionPolicy", cfg.getCredProtect().extensionValue());
      // Spec recommends enforcing the policy server-side as well; the authenticator returns the
      // applied level in attestation and webauthn4j will surface mismatches as
      // VerificationException.
      ext.put("enforceCredentialProtectionPolicy", true);
    }
    return ext;
  }

  /**
   * Completes a registration ceremony by verifying the attestation, applying the tenant's AAGUID
   * policy, and persisting the new credential. Throws {@link BusinessException} with the
   * appropriate {@link ErrorCode} when verification fails ({@code ATTESTATION_INVALID}), MDS trust
   * is rejected ({@code MDS_TRUST_FAILED} / {@code AUTHENTICATOR_REVOKED}), or the AAGUID is not
   * allow-listed ({@code AAGUID_NOT_ALLOWED}). The success audit row is written asynchronously
   * after the transaction commits.
   */
  @Transactional
  public RegistrationResult finishRegistration(RegistrationVerifyRequest req) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    ChallengeRecord stored =
        challengeStore
            .consume(req.ceremonyId())
            .orElseThrow(() -> new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND));
    if (stored.ceremonyType() != CeremonyType.REGISTRATION) {
      // Echoes back as CHALLENGE_NOT_FOUND to the client but log distinctly — this is the
      // signature of a misrouted client or a deliberate cross-ceremony confusion attempt.
      log.warn(
          "register.challenge.wrong_type ceremonyId={} actualType={}",
          req.ceremonyId(),
          stored.ceremonyType());
      throw new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND);
    }

    TenantAttestationPolicy policy =
        policyRepo
            .findByTenantId(cfg.getTenantId())
            .orElseGet(
                () -> policyRepo.save(TenantAttestationPolicy.permissive(cfg.getTenantId())));

    MdsTrustAnchorSource trustAnchors = null;
    if (policy.isMdsStrict()) {
      MdsTrustAnchorSourceHolder holder = mdsHolderProvider.getIfAvailable();
      MdsTrustAnchorSource current = holder == null ? null : holder.current();
      if (current == null) {
        log.error(
            "register.mds.unavailable tenantId={} tenantUserId={} — "
                + "tenant requires mdsStrict but MDS BLOB is not loaded",
            cfg.getTenantId(),
            stored.tenantUserId());
        metrics.getRegistrationFailure().increment();
        throw new BusinessException(ErrorCode.MDS_UNAVAILABLE);
      }
      log.info(
          "register.mds.strict.engaged tenantId={} tenantUserId={}",
          cfg.getTenantId(),
          stored.tenantUserId());
      trustAnchors = current;
    }
    RegistrationVerificationResult result = verifyWithCore(cfg, stored, req, trustAnchors);

    UUID aaguid = bytesToUuid(result.aaguid());
    if (!policy.accepts(aaguid)) {
      log.warn(
          "register.aaguid.rejected tenantId={} tenantUserId={} aaguid={} policyMode={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          aaguid,
          policy.getMode());
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.AAGUID_NOT_ALLOWED);
    }

    long signatureCounter = result.signCount();
    boolean backupEligible = result.backupEligible();
    boolean backupState = result.backupState();

    if (!policy.acceptsSyncable(backupEligible)) {
      log.warn(
          "register.syncable.rejected tenantId={} tenantUserId={} aaguid={} backupEligible={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          aaguid,
          backupEligible);
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.SYNCABLE_NOT_ALLOWED);
    }

    Credential credential =
        Credential.create(
            cfg.getTenantId(),
            stored.tenantUserId(),
            Base64UrlCodec.encode(result.credentialId()),
            result.attestedCredentialData(),
            aaguid,
            req.transports(),
            stored.userHandleB64u(),
            signatureCounter,
            backupEligible,
            backupState);
    if (req.nickname() != null) {
      credential.rename(req.nickname());
    }
    Credential saved = credentialRepo.save(credential);

    auditService.appendAfterCommit(
        AuditEventType.CREDENTIAL_REGISTERED,
        ActorType.END_USER,
        stored.tenantUserId().toString(),
        "CREDENTIAL",
        saved.getId().toString(),
        java.util.Map.of(
            "credentialId",
            saved.getCredentialId(),
            "aaguid",
            aaguid == null ? "" : aaguid.toString()));
    metrics.getRegistrationSuccess().increment();

    log.info(
        "register.success tenantId={} tenantUserId={} credentialDbId={} credentialId={} aaguid={}",
        cfg.getTenantId(),
        stored.tenantUserId(),
        saved.getId(),
        saved.getCredentialId(),
        aaguid);

    return new RegistrationResult(
        saved.getId(), saved.getCredentialId(), aaguid == null ? null : aaguid.toString());
  }

  private TenantUser findOrCreateUser(String externalId, String displayName) {
    UUID tenantId = TenantContextHolder.required().tenantId();
    try {
      return userRepo
          .findByExternalId(externalId)
          .orElseGet(() -> userRepo.save(TenantUser.create(tenantId, externalId, displayName)));
    } catch (org.springframework.dao.DataIntegrityViolationException e) {
      // Concurrent insert raced on uk_tenant_user__tenant_external — fetch the row that the
      // other transaction committed.
      return userRepo
          .findByExternalId(externalId)
          .orElseThrow(
              () ->
                  new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "user creation race", e));
    }
  }

  private static byte[] randomBytes(int len) {
    byte[] buf = new byte[len];
    RNG.nextBytes(buf);
    return buf;
  }

  /**
   * Encodes a UUID as 16 raw bytes for WebAuthn {@code user.id}. Big-endian ordering matches the
   * canonical UUID byte form (most-significant first) — the same encoding webauthn4j produces when
   * the authenticator round-trips the handle back to the server.
   */
  private static byte[] uuidToBytes(java.util.UUID uuid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  /**
   * Decode a 16-byte AAGUID into a {@link UUID}. An all-zero AAGUID maps to the zero UUID {@code
   * 00000000-0000-0000-0000-000000000000} — the same representation webauthn4j's {@code
   * AAGUID.getValue()} produces, so the non-strict and strict registration paths store an identical
   * value for an authenticator that does not report an AAGUID.
   */
  private static UUID bytesToUuid(byte[] aaguid) {
    if (aaguid == null || aaguid.length != 16) {
      return null;
    }
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(aaguid);
    return new UUID(buf.getLong(), buf.getLong());
  }

  private RegistrationVerificationResult verifyWithCore(
      TenantWebauthnConfig cfg,
      ChallengeRecord stored,
      RegistrationVerifyRequest req,
      MdsTrustAnchorSource trustAnchors) {
    RegistrationVerificationRequest verifyReq =
        new RegistrationVerificationRequest(
            Base64UrlCodec.decode(req.attestationObjectB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(stored.challengeB64u()),
            cfg.originList(),
            cfg.getRpId(),
            cfg.getUserVerification().isStrictRequired(),
            trustAnchors);
    try {
      return new RegistrationVerifier().verify(verifyReq);
    } catch (Fido2VerificationException e) {
      mapAndThrow(cfg, stored, e);
      throw new IllegalStateException("unreachable");
    }
  }

  private void mapAndThrow(
      TenantWebauthnConfig cfg, ChallengeRecord stored, Fido2VerificationException e) {
    metrics.getRegistrationFailure().increment();
    switch (e.reason()) {
      case MDS_TRUST_FAILED -> {
        log.warn(
            "register.mds.trust_failed tenantId={} tenantUserId={} detail={}",
            cfg.getTenantId(),
            stored.tenantUserId(),
            e.getMessage());
        auditService.append(
            com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
            com.crosscert.passkey.audit.domain.ActorType.END_USER,
            stored.tenantUserId().toString(),
            "AUTHENTICATOR",
            "trust_anchor_missing",
            java.util.Map.of("reason", e.getMessage()));
        throw new BusinessException(ErrorCode.MDS_TRUST_FAILED, e.getMessage());
      }
      case AUTHENTICATOR_REVOKED -> {
        log.error(
            "register.authenticator.revoked tenantId={} tenantUserId={} detail={}",
            cfg.getTenantId(),
            stored.tenantUserId(),
            e.getMessage());
        auditService.append(
            com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
            com.crosscert.passkey.audit.domain.ActorType.END_USER,
            stored.tenantUserId().toString(),
            "AUTHENTICATOR",
            "revoked",
            java.util.Map.of("reason", e.getMessage()));
        throw new BusinessException(ErrorCode.AUTHENTICATOR_REVOKED, e.getMessage());
      }
      case TRUST_PATH_INVALID -> {
        log.warn(
            "register.mds.trust_failed tenantId={} tenantUserId={} detail={}",
            cfg.getTenantId(),
            stored.tenantUserId(),
            e.getMessage());
        throw new BusinessException(ErrorCode.MDS_TRUST_FAILED, e.getMessage());
      }
      default -> {
        log.warn(
            "register.attestation.invalid tenantId={} tenantUserId={} reason={} detail={}",
            cfg.getTenantId(),
            stored.tenantUserId(),
            e.reason(),
            e.getMessage());
        throw new BusinessException(ErrorCode.ATTESTATION_INVALID, e.getMessage());
      }
    }
  }
}
