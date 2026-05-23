package com.crosscert.passkey.unit.fido2.tpm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.tpm.TpmException;
import com.crosscert.passkey.fido2.tpm.TpmsAttest;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class TpmsAttestTest {

  @Test
  void parses_well_formed_certify_attest() {
    byte[] raw =
        TpmFixtures.attestCertify(/*extraData*/ new byte[] {1, 2, 3}, /*name*/ new byte[32]);
    TpmsAttest attest = TpmsAttest.parse(raw);
    assertThat(attest.magic()).isEqualTo(0xFF544347);
    assertThat(attest.type()).isEqualTo(0x8017);
    assertThat(attest.extraData()).containsExactly(1, 2, 3);
    assertThat(attest.attestedName()).hasSize(32);
  }

  @Test
  void rejects_wrong_magic() {
    byte[] raw = TpmFixtures.attestCertify(new byte[0], new byte[32]);
    ByteBuffer.wrap(raw).putInt(0, 0xDEADBEEF);
    assertThatThrownBy(() -> TpmsAttest.parse(raw))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("magic");
  }

  @Test
  void rejects_wrong_attest_type() {
    byte[] raw = TpmFixtures.attestCertify(new byte[0], new byte[32]);
    raw[4] = (byte) 0x80;
    raw[5] = (byte) 0x18;
    assertThatThrownBy(() -> TpmsAttest.parse(raw))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("ATTEST_CERTIFY");
  }

  @Test
  void rejects_truncated_length_prefix() {
    byte[] raw = new byte[] {(byte) 0xFF, 0x54, 0x43, 0x47, (byte) 0x80, 0x17};
    assertThatThrownBy(() -> TpmsAttest.parse(raw)).isInstanceOf(TpmException.class);
  }

  // ---- Extra negative tests for fail-closed coverage ----

  @Test
  void rejects_trailing_bytes() {
    byte[] raw = TpmFixtures.attestCertify(new byte[] {1, 2, 3}, new byte[32]);
    // Append a spurious extra byte after the valid structure.
    byte[] extended = Arrays.copyOf(raw, raw.length + 1);
    extended[raw.length] = (byte) 0xAB;
    assertThatThrownBy(() -> TpmsAttest.parse(extended))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("trailing bytes");
  }

  @Test
  void rejects_declared_length_exceeding_buffer() {
    // Build a buffer where the extraData length field claims 255 bytes but none follow.
    byte[] raw = TpmFixtures.attestCertify(new byte[0], new byte[32]);
    // qualifiedSigner length is at offset 6 (2B) = 0. extraData length is at offset 8.
    // Overwrite the extraData length to a large value the buffer cannot satisfy.
    raw[8] = (byte) 0x00;
    raw[9] = (byte) 0xFF; // claims 255 bytes
    assertThatThrownBy(() -> TpmsAttest.parse(raw))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("extraData");
  }
}
