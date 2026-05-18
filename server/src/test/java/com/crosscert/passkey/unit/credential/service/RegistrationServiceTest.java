package com.crosscert.passkey.unit.credential.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.RegistrationOptionsResponse;
import com.crosscert.passkey.credential.api.RegistrationVerifyRequest;
import com.crosscert.passkey.credential.challenge.CeremonyType;
import com.crosscert.passkey.credential.challenge.ChallengeRecord;
import com.crosscert.passkey.credential.challenge.ChallengeStore;
import com.crosscert.passkey.credential.challenge.WebauthnCeremonyProperties;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.metrics.CeremonyMetrics;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.service.RegistrationService;
import com.crosscert.passkey.credential.service.TenantWebauthnConfigService;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.webauthn4j.WebAuthnManager;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
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

  @Test
  void beginRegistration_includes_existing_active_credentials_in_excludeCredentials() {
    TenantContextHolder.set(new TenantContext(tenantId, "test-slug"));
    try {
      TenantUser user = TenantUser.create(tenantId, "alice", "Alice");
      when(userRepo.findByExternalId("alice")).thenReturn(Optional.of(user));
      Credential active =
          Credential.create(
              tenantId,
              user.getId(),
              "cred-active",
              new byte[] {1, 2, 3},
              UUID.randomUUID(),
              "usb,nfc",
              "userHandle",
              0L,
              false,
              false);
      // A revoked credential must NOT leak into excludeCredentials — clients would otherwise
      // see a stale exclusion that bricks re-enrolment after the user revoked + re-added.
      Credential revoked =
          Credential.create(
              tenantId,
              user.getId(),
              "cred-revoked",
              new byte[] {4, 5, 6},
              UUID.randomUUID(),
              "internal",
              "userHandle",
              0L,
              false,
              false);
      revoked.revoke();
      when(credentialRepo.findAllByTenantUserId(user.getId())).thenReturn(List.of(active, revoked));
      when(challengeStore.save(any(ChallengeRecord.class))).thenReturn(UUID.randomUUID());

      RegistrationOptionsResponse resp = service.beginRegistration("alice", "Alice");

      assertThat(resp.excludeCredentials())
          .extracting(RegistrationOptionsResponse.ExcludeCredential::id)
          .containsExactly("cred-active");
      assertThat(resp.excludeCredentials().get(0).type()).isEqualTo("public-key");
      assertThat(resp.excludeCredentials().get(0).transports()).isEqualTo("usb,nfc");
    } finally {
      TenantContextHolder.clear();
    }
  }

  @Test
  void beginRegistration_emits_empty_excludeCredentials_for_first_enrolment() {
    TenantContextHolder.set(new TenantContext(tenantId, "test-slug"));
    try {
      TenantUser user = TenantUser.create(tenantId, "bob", "Bob");
      when(userRepo.findByExternalId("bob")).thenReturn(Optional.of(user));
      when(credentialRepo.findAllByTenantUserId(user.getId())).thenReturn(List.of());
      when(challengeStore.save(any(ChallengeRecord.class))).thenReturn(UUID.randomUUID());

      RegistrationOptionsResponse resp = service.beginRegistration("bob", "Bob");

      assertThat(resp.excludeCredentials()).isEmpty();
    } finally {
      TenantContextHolder.clear();
    }
  }

  @Test
  void beginRegistration_encodes_userHandle_as_raw_16_bytes() {
    TenantContextHolder.set(new TenantContext(tenantId, "test-slug"));
    try {
      TenantUser user = TenantUser.create(tenantId, "carol", "Carol");
      when(userRepo.findByExternalId("carol")).thenReturn(Optional.of(user));
      when(credentialRepo.findAllByTenantUserId(user.getId())).thenReturn(List.of());
      when(challengeStore.save(any(ChallengeRecord.class))).thenReturn(UUID.randomUUID());

      RegistrationOptionsResponse resp = service.beginRegistration("carol", "Carol");

      // base64url of 16 bytes → 22 chars unpadded. The legacy text encoding produced 48+ chars.
      byte[] decoded =
          com.crosscert.passkey.credential.webauthn.Base64UrlCodec.decode(resp.user().id());
      assertThat(decoded).hasSize(16);
      // Decoded bytes must round-trip to the same UUID — proves big-endian MSB/LSB layout.
      java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(decoded);
      UUID roundTrip = new UUID(bb.getLong(), bb.getLong());
      assertThat(roundTrip).isEqualTo(user.getId());
    } finally {
      TenantContextHolder.clear();
    }
  }

  @AfterEach
  void clearTenantContext() {
    TenantContextHolder.clear();
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
