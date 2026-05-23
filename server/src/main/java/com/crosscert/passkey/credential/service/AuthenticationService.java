package com.crosscert.passkey.credential.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.TokenPair;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.log.LogSanitiser;
import com.crosscert.passkey.credential.api.AuthenticationOptionsRequest;
import com.crosscert.passkey.credential.api.AuthenticationOptionsResponse;
import com.crosscert.passkey.credential.api.AuthenticationResult;
import com.crosscert.passkey.credential.api.AuthenticationVerifyRequest;
import com.crosscert.passkey.credential.challenge.CeremonyType;
import com.crosscert.passkey.credential.challenge.ChallengeRecord;
import com.crosscert.passkey.credential.challenge.ChallengeStore;
import com.crosscert.passkey.credential.challenge.WebauthnCeremonyProperties;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.webauthn.Base64UrlCodec;
import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private static final SecureRandom RNG = new SecureRandom();

  // Stateless — safe to share a single instance across all ceremonies.
  private static final AuthenticationVerifier ASSERTION_VERIFIER = new AuthenticationVerifier();

  private final TenantWebauthnConfigService configService;
  private final TenantUserRepository userRepo;
  private final CredentialRepository credentialRepo;
  private final ChallengeStore challengeStore;
  private final TokenService tokenService;
  private final AuditService auditService;
  private final WebauthnCeremonyProperties ceremonyProps;
  private final com.crosscert.passkey.ratelimit.RateLimiter rateLimiter;
  private final com.crosscert.passkey.ratelimit.RateLimitProperties rateLimitProps;
  private final com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics;

  /**
   * Begins an authentication ceremony. When {@code externalUserId} is provided, returns the active
   * credentials for that user as {@code allowCredentials}; otherwise leaves the list empty for
   * discoverable-credential / usernameless flows. The challenge is stored in Redis under a ceremony
   * id which must be echoed back to {@link #finishAuthentication}.
   */
  // No DB writes here — challenge lands in Redis (challengeStore) and the audit row is appended in
  // a REQUIRES_NEW tx. readOnly disables Hibernate dirty-checking, so an accidental future write
  // would surface as a clear error instead of silently committing.
  @Transactional(readOnly = true)
  public AuthenticationOptionsResponse beginAuthentication(AuthenticationOptionsRequest req) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    byte[] challenge = randomBytes(ceremonyProps.challengeBytes());
    String challengeB64u = Base64UrlCodec.encode(challenge);

    UUID tenantUserId = null;
    List<AuthenticationOptionsResponse.AllowCredential> allowCredentials = List.of();
    if (req.externalUserId() != null && !req.externalUserId().isBlank()) {
      Optional<TenantUser> user = userRepo.findByExternalId(req.externalUserId());
      if (user.isPresent()) {
        tenantUserId = user.get().getId();
        allowCredentials =
            credentialRepo.findAllByTenantUserId(tenantUserId).stream()
                .filter(Credential::isActive)
                .map(
                    c ->
                        new AuthenticationOptionsResponse.AllowCredential(
                            "public-key", c.getCredentialId(), c.getTransports()))
                .toList();
      }
    }

    ChallengeRecord stored =
        new ChallengeRecord(
            challengeB64u, cfg.getTenantId(), tenantUserId, CeremonyType.AUTHENTICATION, null);
    UUID ceremonyId = challengeStore.save(stored);

    // P2-3: emit start event for funnel drop-off measurement. tenantUserId is null for
    // discoverable-credential flows; that's fine — the row still increments the attempt counter.
    auditService.append(
        AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED,
        ActorType.END_USER,
        tenantUserId == null ? null : tenantUserId.toString(),
        "TENANT_USER",
        tenantUserId == null ? null : tenantUserId.toString(),
        java.util.Map.of(
            "ceremonyId", ceremonyId.toString(), "allowCredentials", allowCredentials.size()));

    log.info(
        "auth.begin tenantId={} tenantUserId={} ceremonyId={} allowCredentials={}",
        cfg.getTenantId(),
        tenantUserId,
        ceremonyId,
        allowCredentials.size());

    return new AuthenticationOptionsResponse(
        ceremonyId,
        challengeB64u,
        cfg.getTimeoutMs(),
        cfg.getRpId(),
        allowCredentials,
        cfg.getUserVerification().name().toLowerCase(Locale.ROOT));
  }

  /**
   * Completes an authentication ceremony: consumes the challenge, verifies the assertion against
   * the stored credential, updates the signature counter, and issues a JWT pair. Throws {@link
   * BusinessException} for missing/expired challenges ({@code CHALLENGE_NOT_FOUND}), revoked
   * credentials ({@code CREDENTIAL_REVOKED}), invalid assertions ({@code ASSERTION_INVALID}), and
   * signature counter regressions ({@code SIGNATURE_COUNTER_REGRESSION}). Success audit is written
   * asynchronously after commit; failure audits stay synchronous for compliance.
   */
  @Transactional
  public AuthenticationResult finishAuthentication(AuthenticationVerifyRequest req) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    enforceCredentialRateLimit(cfg.getTenantId(), req.credentialId());
    ChallengeRecord stored = consumeChallenge(req);
    Credential credential = lookupActiveCredential(req, cfg.getTenantId());
    AuthenticationVerificationResult authnResult = verifyAssertion(cfg, stored, credential, req);

    long newCounter = authnResult.newSignCount();
    updateCounterOrAudit(credential, newCounter);

    // CTAP 2.1 BS flag — may flip between authentications as the user toggles
    // iCloud Keychain / Google Password Manager backup. Reconcile and audit on change so
    // compliance-sensitive RPs can react (e.g. downgrade trust on newly synced credentials).
    boolean previousBackupState = credential.isBackupState();
    boolean newBackupState = authnResult.backupState();
    boolean backupStateChanged = credential.updateBackupState(newBackupState);

    TenantUser user =
        userRepo
            .findById(credential.getTenantUserId())
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    TokenPair tokens = tokenService.issue(cfg.getTenantId(), user.getId(), user.getExternalId());

    auditService.appendAfterCommit(
        AuditEventType.CREDENTIAL_AUTHENTICATED,
        ActorType.END_USER,
        user.getId().toString(),
        "CREDENTIAL",
        credential.getId().toString(),
        java.util.Map.of("credentialId", credential.getCredentialId(), "newCounter", newCounter));
    if (backupStateChanged) {
      // Direction matters operationally:
      //  • false→true (SYNCED): credential now syncs to cloud. Compliance-sensitive RPs may want
      //    to downgrade trust. WARN so it surfaces in security dashboards; the auth itself still
      //    succeeds — the policy decision is left to the audit consumer.
      //  • true→false (UNSYNCED): backup withdrawn / new device — informational.
      boolean syncedDirection = newBackupState && !previousBackupState;
      String eventName =
          syncedDirection ? "auth.backup_state.synced" : "auth.backup_state.unsynced";
      auditService.appendAfterCommit(
          AuditEventType.CREDENTIAL_BACKUP_STATE_CHANGED,
          ActorType.END_USER,
          user.getId().toString(),
          "CREDENTIAL",
          credential.getId().toString(),
          java.util.Map.of(
              "credentialId",
              credential.getCredentialId(),
              "oldBs",
              previousBackupState,
              "newBs",
              newBackupState,
              "direction",
              syncedDirection ? "SYNCED" : "UNSYNCED"));
      if (syncedDirection) {
        log.warn(
            "{} tenantId={} tenantUserId={} credentialDbId={} from={} to={}",
            eventName,
            cfg.getTenantId(),
            user.getId(),
            credential.getId(),
            previousBackupState,
            newBackupState);
        metrics.getBackupStateSyncedFlips().increment();
      } else {
        log.info(
            "{} tenantId={} tenantUserId={} credentialDbId={} from={} to={}",
            eventName,
            cfg.getTenantId(),
            user.getId(),
            credential.getId(),
            previousBackupState,
            newBackupState);
      }
    }
    metrics.getAuthenticationSuccess().increment();

    log.info(
        "auth.success tenantId={} tenantUserId={} credentialDbId={} credentialId={} newCounter={}",
        cfg.getTenantId(),
        user.getId(),
        credential.getId(),
        credential.getCredentialId(),
        newCounter);

    return new AuthenticationResult(
        credential.getId(),
        credential.getTenantUserId(),
        credential.getCredentialId(),
        credential.getSignatureCounter(),
        tokens.accessToken(),
        tokens.refreshToken(),
        tokens.accessExpiresIn());
  }

  /**
   * Per-credential rate limit: defends a single passkey against brute-force / signature-counter
   * regression DoS. Independent of the tenant-wide authenticate bucket — even a tenant under its
   * limit cannot pound a single credential. On miss we audit and throw {@code RATE_LIMIT_EXCEEDED}.
   */
  private void enforceCredentialRateLimit(java.util.UUID tenantId, String credentialId) {
    if (!rateLimitProps.enabled() || credentialId == null || credentialId.isBlank()) {
      return;
    }
    String bucket = tenantId + ":auth-verify:cred:" + credentialId;
    if (!rateLimiter.tryAcquire(bucket, rateLimitProps.credentialAuthVerifyPerMinute())) {
      log.warn(
          "auth.credential.ratelimit.exceeded tenantId={} credentialId={} limit={}",
          tenantId,
          com.crosscert.passkey.common.log.LogSanitiser.forLog(credentialId),
          rateLimitProps.credentialAuthVerifyPerMinute());
      auditService.append(
          AuditEventType.CREDENTIAL_AUTH_RATE_LIMIT,
          ActorType.END_USER,
          null,
          "CREDENTIAL",
          credentialId,
          java.util.Map.of("limit", rateLimitProps.credentialAuthVerifyPerMinute()));
      throw new BusinessException(ErrorCode.RATE_LIMIT_EXCEEDED);
    }
  }

  private ChallengeRecord consumeChallenge(AuthenticationVerifyRequest req) {
    ChallengeRecord stored =
        challengeStore
            .consume(req.ceremonyId())
            .orElseThrow(() -> new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND));
    if (stored.ceremonyType() != CeremonyType.AUTHENTICATION) {
      log.warn(
          "auth.challenge.wrong_type ceremonyId={} actualType={}",
          req.ceremonyId(),
          stored.ceremonyType());
      throw new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND);
    }
    return stored;
  }

  private Credential lookupActiveCredential(
      AuthenticationVerifyRequest req, java.util.UUID tenantId) {
    // Defense-in-depth: the unique constraint on credential is (tenant_id, credential_id) and RLS
    // gates the SELECT, but we still pin the tenant explicitly. A future bug or a code path that
    // accidentally runs with the BYPASSRLS admin connection would otherwise let an attacker who
    // learned another tenant's credentialId impersonate that user.
    Credential credential =
        credentialRepo
            .findByCredentialIdAndTenantId(req.credentialId(), tenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    if (!credential.isActive()) {
      throw new BusinessException(ErrorCode.CREDENTIAL_REVOKED);
    }
    return credential;
  }

  private AuthenticationVerificationResult verifyAssertion(
      TenantWebauthnConfig cfg,
      ChallengeRecord stored,
      Credential credential,
      AuthenticationVerifyRequest req) {
    AuthenticationVerificationRequest verifyReq =
        new AuthenticationVerificationRequest(
            Base64UrlCodec.decode(req.authenticatorDataB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(req.signatureB64u()),
            Base64UrlCodec.decode(stored.challengeB64u()),
            cfg.originList(),
            cfg.getRpId(),
            credential.getPublicKeyCose(),
            cfg.getUserVerification().isStrictRequired());
    try {
      return ASSERTION_VERIFIER.verify(verifyReq);
    } catch (Fido2VerificationException e) {
      log.warn(
          "auth.assertion.invalid tenantId={} credentialId={} reason={} detail={}",
          cfg.getTenantId(),
          LogSanitiser.forLog(req.credentialId()),
          e.reason(),
          LogSanitiser.forLog(e.getMessage()));
      metrics.getAuthenticationFailure().increment();
      throw new BusinessException(ErrorCode.ASSERTION_INVALID, e.getMessage());
    }
  }

  private void updateCounterOrAudit(Credential credential, long newCounter) {
    try {
      credential.updateSignatureCounter(newCounter);
    } catch (BusinessException e) {
      if (e.getErrorCode() == ErrorCode.SIGNATURE_COUNTER_REGRESSION) {
        // Sub-type of the regression — see Credential.RegressionReason. Falls back to UNKNOWN
        // if a future refactor drops the detail string so the log line never goes blank.
        String reason = e.getMessage() == null ? "UNKNOWN" : e.getMessage();
        log.error(
            "auth.signature_counter.regression tenantId={} tenantUserId={} credentialId={} "
                + "storedCounter={} newCounter={} reason={}",
            credential.getTenantId(),
            credential.getTenantUserId(),
            credential.getCredentialId(),
            credential.getSignatureCounter(),
            newCounter,
            reason);
        // FIDO clone-detection signal — auto-revoke the credential so the cloned key cannot keep
        // racing the legitimate device.
        credential.revoke(
            com.crosscert.passkey.credential.domain.CredentialRevokedReason
                .SIGNATURE_COUNTER_REGRESSION);
        auditService.append(
            AuditEventType.SIGNATURE_COUNTER_REGRESSION,
            ActorType.END_USER,
            credential.getTenantUserId().toString(),
            "CREDENTIAL",
            credential.getId().toString(),
            java.util.Map.of(
                "storedCounter",
                credential.getSignatureCounter(),
                "newCounter",
                newCounter,
                "reason",
                reason,
                "autoRevoked",
                true));
        metrics.getSignatureCounterRegression().increment();
        metrics.getAuthenticationFailure().increment();
      }
      throw e;
    }
  }

  private static byte[] randomBytes(int len) {
    byte[] buf = new byte[len];
    RNG.nextBytes(buf);
    return buf;
  }
}
