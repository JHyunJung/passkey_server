package com.crosscert.passkey.unit.credential.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.RegistrationVerifyRequest;
import com.crosscert.passkey.credential.challenge.CeremonyType;
import com.crosscert.passkey.credential.challenge.ChallengeRecord;
import com.crosscert.passkey.credential.challenge.ChallengeStore;
import com.crosscert.passkey.credential.challenge.WebauthnCeremonyProperties;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.metrics.CeremonyMetrics;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.service.RegistrationService;
import com.crosscert.passkey.credential.service.TenantWebauthnConfigService;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.webauthn4j.WebAuthnManager;
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
import org.springframework.beans.factory.ObjectProvider;

/**
 * Core error-path coverage for {@link RegistrationService}. The happy path requires a real
 * attestation fixture and is exercised by the slice/integration tests — this file pins down
 * fail-closed branches that protect us from a refactor silently relaxing the contract.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RegistrationServiceTest {

  @Mock private TenantWebauthnConfigService configService;
  @Mock private TenantAttestationPolicyRepository policyRepo;
  @Mock private TenantUserRepository userRepo;
  @Mock private CredentialRepository credentialRepo;
  @Mock private ChallengeStore challengeStore;
  @Mock private WebAuthnManager nonStrictManager;
  @Mock private ObjectProvider<WebAuthnManager> strictManagerProvider;
  @Mock private AuditService auditService;

  private RegistrationService service;
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
    CeremonyMetrics metrics = new CeremonyMetrics(new SimpleMeterRegistry());

    service =
        new RegistrationService(
            configService,
            policyRepo,
            userRepo,
            credentialRepo,
            challengeStore,
            nonStrictManager,
            strictManagerProvider,
            auditService,
            ceremonyProps,
            metrics);
  }

  @Test
  void finishRegistration_throws_when_challenge_missing() {
    RegistrationVerifyRequest req = sampleReq();
    when(challengeStore.consume(req.ceremonyId())).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.finishRegistration(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CHALLENGE_NOT_FOUND);
  }

  @Test
  void finishRegistration_throws_when_ceremony_type_is_authentication() {
    RegistrationVerifyRequest req = sampleReq();
    ChallengeRecord wrongType =
        new ChallengeRecord("chal", tenantId, UUID.randomUUID(), CeremonyType.AUTHENTICATION, null);
    when(challengeStore.consume(req.ceremonyId())).thenReturn(Optional.of(wrongType));

    assertThatThrownBy(() -> service.finishRegistration(req))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CHALLENGE_NOT_FOUND);
  }

  private static RegistrationVerifyRequest sampleReq() {
    return new RegistrationVerifyRequest(
        UUID.randomUUID(),
        "credId-base64url",
        "Y2xpZW50RGF0YQ",
        "YXR0ZXN0YXRpb25PYmplY3Q",
        "internal",
        null);
  }
}
