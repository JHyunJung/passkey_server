package com.crosscert.passkey.unit.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialRevokedReason;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CredentialRevokeReasonTest {

  @Test
  void revoke_with_reason_records_who_when_why() {
    Credential c = newCredential();
    c.revoke(CredentialRevokedReason.COMPROMISE_SUSPECTED);
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.REVOKED);
    assertThat(c.getRevokedReason()).isEqualTo(CredentialRevokedReason.COMPROMISE_SUSPECTED);
    assertThat(c.getRevokedAt()).isNotNull();
    assertThat(c.isActive()).isFalse();
  }

  @Test
  void revoke_no_arg_defaults_to_admin_forced() {
    Credential c = newCredential();
    c.revoke();
    assertThat(c.getRevokedReason()).isEqualTo(CredentialRevokedReason.ADMIN_FORCED);
  }

  @Test
  void revoke_is_idempotent_and_keeps_first_reason() {
    Credential c = newCredential();
    c.revoke(CredentialRevokedReason.SIGNATURE_COUNTER_REGRESSION);
    var firstAt = c.getRevokedAt();
    c.revoke(CredentialRevokedReason.ADMIN_FORCED);
    assertThat(c.getRevokedReason())
        .isEqualTo(CredentialRevokedReason.SIGNATURE_COUNTER_REGRESSION);
    assertThat(c.getRevokedAt()).isEqualTo(firstAt);
  }

  private static Credential newCredential() {
    return Credential.create(
        UUID.randomUUID(),
        UUID.randomUUID(),
        "credId",
        new byte[] {0x01, 0x02},
        UUID.randomUUID(),
        "internal",
        "uh",
        0L,
        false,
        false);
  }
}
