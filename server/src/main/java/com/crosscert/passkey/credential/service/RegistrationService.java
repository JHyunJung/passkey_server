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
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

  private static final SecureRandom RNG = new SecureRandom();
  private static final int CHALLENGE_LEN = 32;

  // ES256 (-7), RS256 (-257).
  private static final long COSE_ALG_ES256 = -7;
  private static final long COSE_ALG_RS256 = -257;

  private final TenantWebauthnConfigService configService;
  private final TenantAttestationPolicyRepository policyRepo;
  private final TenantUserRepository userRepo;
  private final CredentialRepository credentialRepo;
  private final ChallengeStore challengeStore;
  private final WebAuthnManager webAuthnManager;
  private final AuditService auditService;
  private final com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics;
  private final ObjectConverter objectConverter = new ObjectConverter();
  private final AttestedCredentialDataConverter attestedConverter =
      new AttestedCredentialDataConverter(objectConverter);

  @Transactional
  public RegistrationOptionsResponse beginRegistration(String externalUserId, String displayName) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    TenantUser user = findOrCreateUser(externalUserId, displayName);

    byte[] challenge = randomBytes(CHALLENGE_LEN);
    String challengeB64u = Base64UrlCodec.encode(challenge);
    String userHandle = Base64UrlCodec.encode(user.getId().toString().getBytes());

    ChallengeRecord record =
        new ChallengeRecord(
            challengeB64u, cfg.getTenantId(), user.getId(), CeremonyType.REGISTRATION, userHandle);
    UUID ceremonyId = challengeStore.save(record);

    return new RegistrationOptionsResponse(
        ceremonyId,
        challengeB64u,
        new RegistrationOptionsResponse.Rp(cfg.getRpId(), cfg.getRpName()),
        new RegistrationOptionsResponse.User(userHandle, externalUserId, displayName),
        List.of(
            new RegistrationOptionsResponse.PubKeyCredParam("public-key", COSE_ALG_ES256),
            new RegistrationOptionsResponse.PubKeyCredParam("public-key", COSE_ALG_RS256)),
        cfg.getTimeoutMs(),
        cfg.getAttestationConveyance().name().toLowerCase(),
        new RegistrationOptionsResponse.AuthenticatorSelection(
            cfg.getUserVerification().name().toLowerCase(), "preferred", false));
  }

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

    RegistrationData regData;
    try {
      regData = webAuthnManager.parse(registrationRequest);
      webAuthnManager.verify(regData, params);
    } catch (DataConversionException | VerificationException e) {
      log.warn("Attestation verification failed: {}", e.getMessage());
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.ATTESTATION_INVALID, e.getMessage());
    }

    AttestedCredentialData acd =
        regData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    AAGUID aaguidObj = acd.getAaguid();
    UUID aaguid = aaguidObj == null ? null : aaguidObj.getValue();

    TenantAttestationPolicy policy =
        policyRepo
            .findByTenantId(cfg.getTenantId())
            .orElseGet(
                () -> policyRepo.save(TenantAttestationPolicy.permissive(cfg.getTenantId())));
    if (!policy.accepts(aaguid)) {
      throw new BusinessException(ErrorCode.AAGUID_NOT_ALLOWED);
    }

    // Serialize the full AttestedCredentialData (AAGUID + credentialId + COSE key) so the
    // authentication path can reconstruct the Authenticator object directly.
    byte[] attestedCredBytes = attestedConverter.convert(acd);

    long signatureCounter = regData.getAttestationObject().getAuthenticatorData().getSignCount();
    boolean backupEligible = regData.getAttestationObject().getAuthenticatorData().isFlagBE();
    boolean backupState = regData.getAttestationObject().getAuthenticatorData().isFlagBS();

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

    auditService.append(
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

    return new RegistrationResult(
        saved.getId(), saved.getCredentialId(), aaguid == null ? null : aaguid.toString());
  }

  private TenantUser findOrCreateUser(String externalId, String displayName) {
    UUID tenantId = TenantContextHolder.required().tenantId();
    return userRepo
        .findByExternalId(externalId)
        .orElseGet(() -> userRepo.save(TenantUser.create(tenantId, externalId, displayName)));
  }

  private static byte[] randomBytes(int len) {
    byte[] buf = new byte[len];
    RNG.nextBytes(buf);
    return buf;
  }
}
