package com.crosscert.passkey.unit.credential.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.domain.Credential;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Domain invariants for FIDO2 clone detection. */
class CredentialSignatureCounterTest {

  private Credential newCredential(long initialCounter) {
    return Credential.create(
        UUID.randomUUID(),
        UUID.randomUUID(),
        "cred-id-b64u",
        new byte[] {1, 2, 3},
        UUID.randomUUID(),
        "internal",
        "user-handle-b64u",
        initialCounter,
        false,
        false);
  }

  @Test
  void counter_increases_monotonically() {
    Credential c = newCredential(5);
    c.updateSignatureCounter(6);
    assertThat(c.getSignatureCounter()).isEqualTo(6);
    c.updateSignatureCounter(100);
    assertThat(c.getSignatureCounter()).isEqualTo(100);
  }

  @Test
  void counter_zero_is_no_op_path() {
    Credential c = newCredential(0);
    c.updateSignatureCounter(0); // authenticator without a counter — accepted
    assertThat(c.getSignatureCounter()).isZero();
  }

  @Test
  void counter_regression_rejected() {
    Credential c = newCredential(10);
    assertThatThrownBy(() -> c.updateSignatureCounter(9))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.SIGNATURE_COUNTER_REGRESSION);
  }

  @Test
  void counter_equal_to_stored_rejected() {
    Credential c = newCredential(10);
    assertThatThrownBy(() -> c.updateSignatureCounter(10))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.SIGNATURE_COUNTER_REGRESSION);
  }

  @Test
  void counter_downgrade_to_zero_rejected_when_stored_is_positive() {
    // FIDO2 clone signal: an authenticator that previously advertised a counter (stored > 0)
    // suddenly reports 0. Treated as regression. Some legitimate firmware-reset cases will trip
    // this; the trade-off is intentional — false positives are operationally cheap to recover
    // (re-enrol the passkey), false negatives let a cloned key keep authenticating.
    Credential c = newCredential(50);
    assertThatThrownBy(() -> c.updateSignatureCounter(0))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.SIGNATURE_COUNTER_REGRESSION);
  }

  @Test
  void regression_detail_carries_DOWNGRADE_TO_ZERO_reason() {
    Credential c = newCredential(50);
    assertThatThrownBy(() -> c.updateSignatureCounter(0))
        .isInstanceOf(BusinessException.class)
        .hasMessage(Credential.RegressionReason.DOWNGRADE_TO_ZERO.name());
  }

  @Test
  void regression_detail_carries_REPLAY_reason() {
    Credential c = newCredential(10);
    assertThatThrownBy(() -> c.updateSignatureCounter(10))
        .isInstanceOf(BusinessException.class)
        .hasMessage(Credential.RegressionReason.REPLAY.name());
  }

  @Test
  void regression_detail_carries_BACKWARDS_reason() {
    Credential c = newCredential(10);
    assertThatThrownBy(() -> c.updateSignatureCounter(9))
        .isInstanceOf(BusinessException.class)
        .hasMessage(Credential.RegressionReason.BACKWARDS.name());
  }
}
