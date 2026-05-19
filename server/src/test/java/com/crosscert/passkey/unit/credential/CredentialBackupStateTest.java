package com.crosscert.passkey.unit.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.Credential;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Pins {@link Credential#updateBackupState(boolean)} semantics. The boolean return value drives the
 * audit-emit branch in {@code AuthenticationService.finishAuthentication} — flipping it silently
 * would mute the {@code CREDENTIAL_BACKUP_STATE_CHANGED} compliance signal.
 */
class CredentialBackupStateTest {

  private Credential newCredential(boolean initialBs) {
    return Credential.create(
        UUID.randomUUID(),
        UUID.randomUUID(),
        "cred-id",
        new byte[] {1, 2, 3},
        UUID.randomUUID(),
        "internal",
        "userHandle",
        0L,
        true /* backupEligible */,
        initialBs);
  }

  @Test
  void returns_false_and_no_change_when_state_matches() {
    Credential c = newCredential(false);

    boolean changed = c.updateBackupState(false);

    assertThat(changed).isFalse();
    assertThat(c.isBackupState()).isFalse();
  }

  @Test
  void returns_true_and_flips_when_state_differs() {
    Credential c = newCredential(false);

    boolean changed = c.updateBackupState(true);

    assertThat(changed).isTrue();
    assertThat(c.isBackupState()).isTrue();
  }

  @Test
  void detects_flip_back_to_false() {
    Credential c = newCredential(true);

    boolean changed = c.updateBackupState(false);

    assertThat(changed).isTrue();
    assertThat(c.isBackupState()).isFalse();
  }
}
