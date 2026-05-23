package com.crosscert.passkey.unit.credential.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.AuthenticationVerifyRequest;
import com.crosscert.passkey.credential.challenge.CeremonyType;
import com.crosscert.passkey.credential.challenge.ChallengeRecord;
import com.crosscert.passkey.credential.challenge.ChallengeStore;
import com.crosscert.passkey.credential.challenge.WebauthnCeremonyProperties;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.metrics.CeremonyMetrics;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.service.AuthenticationService;
import com.crosscert.passkey.credential.service.TenantWebauthnConfigService;
import com.crosscert.passkey.ratelimit.RateLimitProperties;
import com.crosscert.passkey.ratelimit.RateLimiter;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Core error-path coverage for {@link AuthenticationService}. The happy path requires a full
 * webauthn4j attestation fixture and lives in the slice tests — these unit tests pin down the
 * fail-closed branches (challenge missing / ceremony type mismatch / credential not found /
 * revoked) so an accidental refactor cannot loosen the contract silently.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceTest {

  @Mock private TenantWebauthnConfigService configService;
  @Mock private TenantUserRepository userRepo;
  @Mock private CredentialRepository credentialRepo;
  @Mock private ChallengeStore challengeStore;
  @Mock private TokenService tokenService;
  @Mock private AuditService auditService;
  @Mock private RateLimiter rateLimiter;

  private AuthenticationService service;
  private final UUID tenantId = UUID.randomUUID();

  @BeforeEach
  void setUp() {
    TenantWebauthnConfig cfg =
        TenantWebauthnConfig.create(
            tenantId,
            "passkey.example.com",
            "Passkey",
            java.util.List.of("https://passkey.example.com"));
    when(configService.requireCurrent()).thenReturn(cfg);

    WebauthnCeremonyProperties ceremonyProps =
        new WebauthnCeremonyProperties(32, Duration.ofMinutes(5));
    RateLimitProperties rlProps = new RateLimitProperties(false, 30, 60, 120, 5, 10);
    when(rateLimiter.tryAcquire(any(), org.mockito.ArgumentMatchers.anyInt())).thenReturn(true);
    CeremonyMetrics metrics = new CeremonyMetrics(new SimpleMeterRegistry());

    service =
        new AuthenticationService(
            configService,
            userRepo,
            credentialRepo,
            challengeStore,
            tokenService,
            auditService,
            ceremonyProps,
            rateLimiter,
            rlProps,
            metrics);
  }

  @Test
  void finishAuthentication_throws_when_challenge_missing() {
    AuthenticationVerifyRequest req = sampleReq();
    when(challengeStore.consume(req.ceremonyId())).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.finishAuthentication(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CHALLENGE_NOT_FOUND);
  }

  @Test
  void finishAuthentication_throws_when_ceremony_type_is_registration() {
    AuthenticationVerifyRequest req = sampleReq();
    ChallengeRecord wrongType =
        new ChallengeRecord("chal", tenantId, UUID.randomUUID(), CeremonyType.REGISTRATION, null);
    when(challengeStore.consume(req.ceremonyId())).thenReturn(Optional.of(wrongType));

    assertThatThrownBy(() -> service.finishAuthentication(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CHALLENGE_NOT_FOUND);
  }

  @Test
  void finishAuthentication_throws_when_credential_not_found() {
    AuthenticationVerifyRequest req = sampleReq();
    ChallengeRecord ok =
        new ChallengeRecord("chal", tenantId, UUID.randomUUID(), CeremonyType.AUTHENTICATION, null);
    when(challengeStore.consume(req.ceremonyId())).thenReturn(Optional.of(ok));
    when(credentialRepo.findByCredentialIdAndTenantId(req.credentialId(), tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.finishAuthentication(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CREDENTIAL_NOT_FOUND);
  }

  @Test
  void finishAuthentication_throws_when_credential_revoked() {
    AuthenticationVerifyRequest req = sampleReq();
    ChallengeRecord ok =
        new ChallengeRecord("chal", tenantId, UUID.randomUUID(), CeremonyType.AUTHENTICATION, null);
    when(challengeStore.consume(req.ceremonyId())).thenReturn(Optional.of(ok));
    Credential revoked = revokedCredentialFixture(tenantId);
    when(credentialRepo.findByCredentialIdAndTenantId(req.credentialId(), tenantId))
        .thenReturn(Optional.of(revoked));

    assertThatThrownBy(() -> service.finishAuthentication(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
  }

  private static AuthenticationVerifyRequest sampleReq() {
    return new AuthenticationVerifyRequest(
        UUID.randomUUID(),
        "credId-base64url",
        "Y2xpZW50RGF0YQ",
        "YXV0aGVudGljYXRvckRhdGE",
        "c2lnbmF0dXJl",
        null);
  }

  private static Credential revokedCredentialFixture(UUID tenantId) {
    Credential c =
        Credential.create(
            tenantId,
            UUID.randomUUID(),
            "credId-base64url",
            new byte[] {0},
            null,
            null,
            "internal",
            0L,
            true,
            true);
    // Force REVOKED status via reflection — domain factory only emits ACTIVE.
    try {
      java.lang.reflect.Field f = Credential.class.getDeclaredField("status");
      f.setAccessible(true);
      f.set(c, CredentialStatus.REVOKED);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
    return c;
  }
}
