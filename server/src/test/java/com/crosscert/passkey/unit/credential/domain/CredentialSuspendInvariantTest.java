package com.crosscert.passkey.unit.credential.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CredentialSuspendInvariantTest {

  private Credential newCredential() {
    return Credential.create(
        UUID.randomUUID(),
        UUID.randomUUID(),
        "cred-id-base64url",
        new byte[] {1, 2, 3},
        UUID.randomUUID(),
        "internal",
        "user-handle",
        0L,
        false,
        false);
  }

  @Test
  void suspend_active_transitionsToSuspended_andRecordsReason() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.SUSPENDED);
    assertThat(c.getSuspendedAt()).isNotNull();
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
    assertThat(c.isSuspended()).isTrue();
    assertThat(c.isActive()).isFalse();
  }

  @Test
  void suspend_isIdempotent() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    var firstAt = c.getSuspendedAt();
    c.suspend("MDS_REVOKED:USER_VERIFICATION_BYPASS"); // no-op
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.SUSPENDED);
    assertThat(c.getSuspendedAt()).isEqualTo(firstAt);
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
  }

  @Test
  void suspend_onRevoked_throwsInvalidState() {
    Credential c = newCredential();
    c.revoke();
    assertThatThrownBy(() -> c.suspend("MDS_REVOKED:REVOKED"))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.CREDENTIAL_INVALID_STATE);
  }

  @Test
  void unsuspend_suspendedToActive_recordsActorAndPreservesHistory() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    var suspAt = c.getSuspendedAt();
    c.unsuspend("admin-uuid");
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.ACTIVE);
    assertThat(c.getUnsuspendedAt()).isNotNull();
    assertThat(c.getUnsuspendedBy()).isEqualTo("admin-uuid");
    // history preserved
    assertThat(c.getSuspendedAt()).isEqualTo(suspAt);
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
  }

  @Test
  void unsuspend_onActive_throwsInvalidState() {
    Credential c = newCredential();
    assertThatThrownBy(() -> c.unsuspend("admin"))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.CREDENTIAL_INVALID_STATE);
  }

  @Test
  void unsuspend_onRevoked_throwsInvalidState() {
    Credential c = newCredential();
    c.revoke();
    assertThatThrownBy(() -> c.unsuspend("admin"))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.CREDENTIAL_INVALID_STATE);
  }

  @Test
  void revoke_onSuspended_succeedsAndPreservesSuspensionHistory() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    var suspAt = c.getSuspendedAt();
    c.revoke(); // PO escalation path — suspended → revoked is allowed
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.REVOKED);
    assertThat(c.getRevokedAt()).isNotNull();
    // suspension history preserved for forensics
    assertThat(c.getSuspendedAt()).isEqualTo(suspAt);
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
  }
}
