package com.crosscert.passkey.credential.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.TokenPair;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.AuthenticationOptionsRequest;
import com.crosscert.passkey.credential.api.AuthenticationOptionsResponse;
import com.crosscert.passkey.credential.api.AuthenticationResult;
import com.crosscert.passkey.credential.api.AuthenticationVerifyRequest;
import com.crosscert.passkey.credential.challenge.CeremonyType;
import com.crosscert.passkey.credential.challenge.ChallengeRecord;
import com.crosscert.passkey.credential.challenge.ChallengeStore;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.webauthn.Base64UrlCodec;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
  private static final int CHALLENGE_LEN = 32;

  private final TenantWebauthnConfigService configService;
  private final TenantUserRepository userRepo;
  private final CredentialRepository credentialRepo;
  private final ChallengeStore challengeStore;
  private final WebAuthnManager webAuthnManager;
  private final TokenService tokenService;
  private final AuditService auditService;
  private final com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics;
  private final ObjectConverter objectConverter = new ObjectConverter();
  private final AttestedCredentialDataConverter attestedConverter =
      new AttestedCredentialDataConverter(objectConverter);

  @Transactional
  public AuthenticationOptionsResponse beginAuthentication(AuthenticationOptionsRequest req) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    byte[] challenge = randomBytes(CHALLENGE_LEN);
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
        cfg.getUserVerification().name().toLowerCase());
  }

  @Transactional
  public AuthenticationResult finishAuthentication(AuthenticationVerifyRequest req) {
    TenantWebauthnConfig cfg = configService.requireCurrent();
    ChallengeRecord stored = consumeChallenge(req);
    Credential credential = lookupActiveCredential(req);
    AuthenticationData authnData = verifyAssertion(cfg, stored, credential, req);

    long newCounter = authnData.getAuthenticatorData().getSignCount();
    updateCounterOrAudit(credential, newCounter);

    TenantUser user =
        userRepo
            .findById(credential.getTenantUserId())
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    TokenPair tokens = tokenService.issue(cfg.getTenantId(), user.getId(), user.getExternalId());

    auditService.append(
        AuditEventType.CREDENTIAL_AUTHENTICATED,
        ActorType.END_USER,
        user.getId().toString(),
        "CREDENTIAL",
        credential.getId().toString(),
        java.util.Map.of("credentialId", credential.getCredentialId(), "newCounter", newCounter));
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

  private ChallengeRecord consumeChallenge(AuthenticationVerifyRequest req) {
    ChallengeRecord stored =
        challengeStore
            .consume(req.ceremonyId())
            .orElseThrow(() -> new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND));
    if (stored.ceremonyType() != CeremonyType.AUTHENTICATION) {
      throw new BusinessException(ErrorCode.CHALLENGE_NOT_FOUND);
    }
    return stored;
  }

  private Credential lookupActiveCredential(AuthenticationVerifyRequest req) {
    Credential credential =
        credentialRepo
            .findByCredentialId(req.credentialId())
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    if (!credential.isActive()) {
      throw new BusinessException(ErrorCode.CREDENTIAL_REVOKED);
    }
    return credential;
  }

  private AuthenticationData verifyAssertion(
      TenantWebauthnConfig cfg,
      ChallengeRecord stored,
      Credential credential,
      AuthenticationVerifyRequest req) {
    AttestedCredentialData acd = attestedConverter.convert(credential.getPublicKeyCose());
    Authenticator authenticator =
        new AuthenticatorImpl(
            acd, new NoneAttestationStatement(), credential.getSignatureCounter());

    byte[] userHandle =
        req.userHandleB64u() == null ? null : Base64UrlCodec.decode(req.userHandleB64u());
    AuthenticationRequest authnReq =
        new AuthenticationRequest(
            Base64UrlCodec.decode(req.credentialId()),
            userHandle,
            Base64UrlCodec.decode(req.authenticatorDataB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(req.signatureB64u()));

    Challenge challenge = new DefaultChallenge(Base64UrlCodec.decode(stored.challengeB64u()));
    Set<Origin> origins = new LinkedHashSet<>();
    for (String o : cfg.originList()) {
      origins.add(new Origin(o));
    }
    ServerProperty serverProperty = new ServerProperty(origins, cfg.getRpId(), challenge);
    boolean userVerificationRequired = cfg.getUserVerification().name().equals("REQUIRED");
    AuthenticationParameters params =
        new AuthenticationParameters(
            serverProperty, authenticator, null, userVerificationRequired, true);

    try {
      AuthenticationData authnData = webAuthnManager.parse(authnReq);
      webAuthnManager.verify(authnData, params);
      return authnData;
    } catch (DataConversionException | VerificationException e) {
      log.warn(
          "auth.assertion.invalid tenantId={} credentialId={} reason={}",
          cfg.getTenantId(),
          sanitiseForLog(req.credentialId()),
          sanitiseForLog(e.getMessage()));
      metrics.getAuthenticationFailure().increment();
      throw new BusinessException(ErrorCode.ASSERTION_INVALID, e.getMessage());
    }
  }

  private void updateCounterOrAudit(Credential credential, long newCounter) {
    try {
      credential.updateSignatureCounter(newCounter);
    } catch (BusinessException e) {
      if (e.getErrorCode() == ErrorCode.SIGNATURE_COUNTER_REGRESSION) {
        log.error(
            "auth.signature_counter.regression tenantId={} tenantUserId={} credentialId={} "
                + "storedCounter={} newCounter={}",
            credential.getTenantId(),
            credential.getTenantUserId(),
            credential.getCredentialId(),
            credential.getSignatureCounter(),
            newCounter);
        auditService.append(
            AuditEventType.SIGNATURE_COUNTER_REGRESSION,
            ActorType.END_USER,
            credential.getTenantUserId().toString(),
            "CREDENTIAL",
            credential.getId().toString(),
            java.util.Map.of(
                "storedCounter", credential.getSignatureCounter(), "newCounter", newCounter));
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

  /** Defends against log injection: strips CR/LF from user-controlled strings before logging. */
  private static String sanitiseForLog(String s) {
    if (s == null) {
      return "";
    }
    return s.replace('\n', '_').replace('\r', '_');
  }
}
