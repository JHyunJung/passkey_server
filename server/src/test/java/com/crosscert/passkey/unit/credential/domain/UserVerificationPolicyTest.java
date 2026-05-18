package com.crosscert.passkey.unit.credential.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.UserVerificationPolicy;
import org.junit.jupiter.api.Test;

/**
 * Pins the server-side enforcement mapping. A future refactor that loosens REQUIRED or tightens
 * PREFERRED would alter every tenant's effective UV policy — this test trips it before the change
 * ships.
 */
class UserVerificationPolicyTest {

  @Test
  void required_is_strict() {
    assertThat(UserVerificationPolicy.REQUIRED.isStrictRequired()).isTrue();
  }

  @Test
  void preferred_is_best_effort() {
    assertThat(UserVerificationPolicy.PREFERRED.isStrictRequired()).isFalse();
  }

  @Test
  void discouraged_is_best_effort() {
    assertThat(UserVerificationPolicy.DISCOURAGED.isStrictRequired()).isFalse();
  }
}
