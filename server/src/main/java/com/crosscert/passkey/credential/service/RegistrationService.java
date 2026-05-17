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
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.webauthn.Base64UrlCodec;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.metadata.exception.BadStatusException;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.TrustAnchorNotFoundException;
import com.webauthn4j.verifier.exception.VerificationException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
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
  private final WebAuthnManager nonStrictManager;
  private final ObjectProvider<WebAuthnManager> strictManagerProvider;
  private final AuditService auditService;
  private final WebauthnCeremonyProperties ceremonyProps;
  private final com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics;
  private final ObjectConverter objectConverter = new ObjectConverter();
  private final AttestedCredentialDataConverter attestedConverter =
      new AttestedCredentialDataConverter(objectConverter);

  public RegistrationService(
      TenantWebauthnConfigService configService,
      TenantAttestationPolicyRepository policyRepo,
      TenantUserRepository userRepo,
      CredentialRepository credentialRepo,
      ChallengeStore challengeStore,
      @Qualifier("nonStrictWebAuthnManager") WebAuthnManager nonStrictManager,
      @Qualifier("strictWebAuthnManager") ObjectProvider<WebAuthnManager> strictManagerProvider,
      AuditService auditService,
      WebauthnCeremonyProperties ceremonyProps,
      com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics) {
    this.configService = configService;
    this.policyRepo = policyRepo;
    this.userRepo = userRepo;
    this.credentialRepo = credentialRepo;
    this.challengeStore = challengeStore;
    this.nonStrictManager = nonStrictManager;
    this.strictManagerProvider = strictManagerProvider;
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
    String userHandle =
        Base64UrlCodec.encode(user.getId().toString().getBytes(StandardCharsets.UTF_8));

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

    log.info(
        "register.begin tenantId={} tenantUserId={} externalUserId={} ceremonyId={}",
        cfg.getTenantId(),
        user.getId(),
        externalUserId,
        ceremonyId);

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
      throw new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND);
    }

    byte[] attestationObject = Base64UrlCodec.decode(req.attestationObjectB64u());
    byte[] clientDataJSON = Base64UrlCodec.decode(req.clientDataJsonB64u());
    RegistrationRequest registrationRequest =
        new RegistrationRequest(attestationObject, clientDataJSON);

    Challenge challenge = new DefaultChallenge(Base64UrlCodec.decode(stored.challengeB64u()));
    Set<Origin> origins = new LinkedHashSet<>();
    for (String o : cfg.originList()) {
      origins.add(new Origin(o));
    }
    ServerProperty serverProperty = new ServerProperty(origins, cfg.getRpId(), challenge);

    boolean userVerificationRequired = cfg.getUserVerification().name().equals("REQUIRED");
    RegistrationParameters params =
        new RegistrationParameters(serverProperty, null, userVerificationRequired, true);

    TenantAttestationPolicy policy =
        policyRepo
            .findByTenantId(cfg.getTenantId())
            .orElseGet(
                () -> policyRepo.save(TenantAttestationPolicy.permissive(cfg.getTenantId())));

    WebAuthnManager manager = nonStrictManager;
    if (policy.isMdsStrict()) {
      manager = strictManagerProvider.getIfAvailable();
      if (manager == null) {
        log.error(
            "register.mds.unavailable tenantId={} tenantUserId={} — "
                + "tenant requires mdsStrict but server has passkey.mds.enabled=false",
            cfg.getTenantId(),
            stored.tenantUserId());
        metrics.getRegistrationFailure().increment();
        throw new BusinessException(ErrorCode.MDS_UNAVAILABLE);
      }
      log.info(
          "register.mds.strict.engaged tenantId={} tenantUserId={}",
          cfg.getTenantId(),
          stored.tenantUserId());
    }

    RegistrationData regData;
    try {
      regData = manager.parse(registrationRequest);
      manager.verify(regData, params);
    } catch (BadStatusException e) {
      // FIDO MDS reported REVOKED / ATTESTATION_KEY_COMPROMISE / USER_VERIFICATION_BYPASS / etc.
      log.error(
          "register.authenticator.revoked tenantId={} tenantUserId={} reason={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.getMessage());
      auditService.append(
          com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          stored.tenantUserId().toString(),
          "AUTHENTICATOR",
          "revoked",
          java.util.Map.of("reason", String.valueOf(e.getMessage())));
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.AUTHENTICATOR_REVOKED, e.getMessage());
    } catch (TrustAnchorNotFoundException e) {
      // Strict mode: no trust anchor matched the AAGUID — authenticator not in MDS.
      log.warn(
          "register.mds.trust_failed tenantId={} tenantUserId={} reason={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.getMessage());
      auditService.append(
          com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          stored.tenantUserId().toString(),
          "AUTHENTICATOR",
          "trust_anchor_missing",
          java.util.Map.of("reason", String.valueOf(e.getMessage())));
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.MDS_TRUST_FAILED, e.getMessage());
    } catch (DataConversionException | VerificationException e) {
      log.warn(
          "register.attestation.invalid tenantId={} tenantUserId={} reason={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.getMessage());
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.ATTESTATION_INVALID, e.getMessage());
    }

    AttestedCredentialData acd =
        regData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    AAGUID aaguidObj = acd.getAaguid();
    UUID aaguid = aaguidObj == null ? null : aaguidObj.getValue();

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

    // Serialize the full AttestedCredentialData (AAGUID + credentialId + COSE key) so the
    // authentication path can reconstruct the Authenticator object directly.
    byte[] attestedCredBytes = attestedConverter.convert(acd);

    long signatureCounter = regData.getAttestationObject().getAuthenticatorData().getSignCount();
    boolean backupEligible = regData.getAttestationObject().getAuthenticatorData().isFlagBE();
    boolean backupState = regData.getAttestationObject().getAuthenticatorData().isFlagBS();

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
            Base64UrlCodec.encode(acd.getCredentialId()),
            attestedCredBytes,
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
}
