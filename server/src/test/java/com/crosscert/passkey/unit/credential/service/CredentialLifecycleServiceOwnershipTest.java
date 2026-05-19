package com.crosscert.passkey.unit.credential.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.repository.TenantWebauthnConfigRepository;
import com.crosscert.passkey.credential.service.CredentialLifecycleService;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Locks in IDOR-defence for the RP-facing rename/revoke endpoints. Without this guard a malicious
 * RP backend (or a bug in the RP that mishandles its end-user session) could mutate any credential
 * under the same tenant — RLS only enforces tenant isolation, not within-tenant ownership.
 */
@ExtendWith(MockitoExtension.class)
class CredentialLifecycleServiceOwnershipTest {

  @Mock private CredentialRepository credentialRepo;
  @Mock private TenantUserRepository tenantUserRepo;
  @Mock private TenantWebauthnConfigRepository webauthnConfigRepo;
  @Mock private TenantAttestationPolicyRepository attestationPolicyRepo;
  @Mock private AuditService auditService;
  @Mock private RefreshTokenRepository refreshTokenRepo;

  private CredentialLifecycleService service;

  private final UUID tenantId = UUID.randomUUID();

  @BeforeEach
  void setUp() {
    com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics =
        new com.crosscert.passkey.credential.metrics.CeremonyMetrics(
            new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    service =
        new CredentialLifecycleService(
            credentialRepo,
            tenantUserRepo,
            webauthnConfigRepo,
            attestationPolicyRepo,
            auditService,
            refreshTokenRepo,
            metrics);
  }

  private Credential credentialFor(UUID tenantUserId) {
    return Credential.create(
        tenantId,
        tenantUserId,
        "cred-id",
        new byte[] {1},
        UUID.randomUUID(),
        "internal",
        "userHandle",
        0L,
        false,
        false);
  }

  @Test
  void renameForUser_succeeds_for_owner() {
    UUID credentialId = UUID.randomUUID();
    TenantUser alice = TenantUser.create(tenantId, "alice", "Alice");
    Credential cred = credentialFor(alice.getId());
    when(credentialRepo.findById(credentialId)).thenReturn(Optional.of(cred));
    when(tenantUserRepo.findByExternalId("alice")).thenReturn(Optional.of(alice));

    service.renameForUser(credentialId, "alice", "Mac");

    verify(auditService).append(any(), any(), eq(alice.getId().toString()), any(), any(), any());
  }

  @Test
  void renameForUser_returns_CREDENTIAL_NOT_FOUND_when_other_user_attempts() {
    UUID credentialId = UUID.randomUUID();
    TenantUser alice = TenantUser.create(tenantId, "alice", "Alice");
    TenantUser mallory = TenantUser.create(tenantId, "mallory", "Mallory");
    Credential aliceCred = credentialFor(alice.getId());
    when(credentialRepo.findById(credentialId)).thenReturn(Optional.of(aliceCred));
    when(tenantUserRepo.findByExternalId("mallory")).thenReturn(Optional.of(mallory));

    // Mallory knows aliceCred's UUID and tries to rename it under her own externalUserId.
    assertThatThrownBy(() -> service.renameForUser(credentialId, "mallory", "stolen"))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CREDENTIAL_NOT_FOUND);

    verify(auditService, never()).append(any(), any(), any(), any(), any(), any());
  }

  @Test
  void renameForUser_returns_CREDENTIAL_NOT_FOUND_when_user_unknown() {
    UUID credentialId = UUID.randomUUID();
    Credential cred = credentialFor(UUID.randomUUID());
    when(credentialRepo.findById(credentialId)).thenReturn(Optional.of(cred));
    when(tenantUserRepo.findByExternalId("ghost")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.renameForUser(credentialId, "ghost", "x"))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CREDENTIAL_NOT_FOUND);
  }

  @Test
  void revokeForUser_succeeds_for_owner_and_burns_refresh_tokens() {
    UUID credentialId = UUID.randomUUID();
    TenantUser alice = TenantUser.create(tenantId, "alice", "Alice");
    Credential cred = credentialFor(alice.getId());
    when(credentialRepo.findById(credentialId)).thenReturn(Optional.of(cred));
    when(tenantUserRepo.findByExternalId("alice")).thenReturn(Optional.of(alice));
    when(refreshTokenRepo.revokeAllByTenantUserId(
            eq(alice.getId()), eq(RevokedReason.CREDENTIAL_REVOKED), any(OffsetDateTime.class)))
        .thenReturn(2);

    service.revokeForUser(credentialId, "alice");

    verify(refreshTokenRepo)
        .revokeAllByTenantUserId(
            eq(alice.getId()), eq(RevokedReason.CREDENTIAL_REVOKED), any(OffsetDateTime.class));
  }

  @Test
  void revokeForUser_returns_CREDENTIAL_NOT_FOUND_when_other_user_attempts() {
    UUID credentialId = UUID.randomUUID();
    TenantUser alice = TenantUser.create(tenantId, "alice", "Alice");
    TenantUser mallory = TenantUser.create(tenantId, "mallory", "Mallory");
    Credential aliceCred = credentialFor(alice.getId());
    when(credentialRepo.findById(credentialId)).thenReturn(Optional.of(aliceCred));
    when(tenantUserRepo.findByExternalId("mallory")).thenReturn(Optional.of(mallory));

    assertThatThrownBy(() -> service.revokeForUser(credentialId, "mallory"))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.CREDENTIAL_NOT_FOUND);

    verify(refreshTokenRepo, never())
        .revokeAllByTenantUserId(any(), any(), any(OffsetDateTime.class));
  }
}
