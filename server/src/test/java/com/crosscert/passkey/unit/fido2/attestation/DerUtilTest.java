package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.DerUtil;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class DerUtilTest {

  @Test
  void unwrap_octet_string_short_form() throws Exception {
    byte[] der = {0x04, 0x03, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC};
    assertThat(DerUtil.unwrapOctetString(der, "test")).containsExactly(0xAA, 0xBB, 0xCC);
  }

  @Test
  void unwrap_octet_string_long_form_0x81() throws Exception {
    byte[] content = new byte[200];
    for (int i = 0; i < 200; i++) content[i] = (byte) (i & 0xff);
    byte[] der = new byte[3 + 200];
    der[0] = 0x04;
    der[1] = (byte) 0x81;
    der[2] = (byte) 200;
    System.arraycopy(content, 0, der, 3, 200);
    assertThat(DerUtil.unwrapOctetString(der, "test")).isEqualTo(content);
  }

  @Test
  void unwrap_rejects_wrong_tag() {
    byte[] der = {0x30, 0x02, 0x00, 0x00};
    assertThatThrownBy(() -> DerUtil.unwrapOctetString(der, "outer"))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void unwrap_rejects_unsupported_long_form_0x82() {
    byte[] der = {0x04, (byte) 0x82, 0x00, 0x02, 0x00, 0x00};
    assertThatThrownBy(() -> DerUtil.unwrapOctetString(der, "outer"))
        .isInstanceOf(Fido2VerificationException.class)
        .hasMessageContaining("unsupported");
  }

  @Test
  void unwrap_rejects_truncated() {
    byte[] der = {0x04};
    assertThatThrownBy(() -> DerUtil.unwrapOctetString(der, "outer"))
        .isInstanceOf(Fido2VerificationException.class);
  }

  @Test
  void unwrap_rejects_length_mismatch() {
    // OCTET STRING declares length 5, but only 2 content bytes follow.
    byte[] der = {0x04, 0x05, 0x01, 0x02};
    assertThatThrownBy(() -> DerUtil.unwrapOctetString(der, "outer"))
        .isInstanceOf(Fido2VerificationException.class);
  }

  @Test
  void extract_apple_nonce_round_trip() throws Exception {
    byte[] nonce = "01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8);
    byte[] octet = concat(new byte[] {0x04, (byte) nonce.length}, nonce);
    byte[] ctx = concat(new byte[] {(byte) 0xA1, (byte) octet.length}, octet);
    byte[] seq = concat(new byte[] {0x30, (byte) ctx.length}, ctx);
    assertThat(DerUtil.extractAppleNonce(seq)).isEqualTo(nonce);
  }

  @Test
  void extract_android_key_attestation_challenge_index_4() throws Exception {
    byte[] challenge = "android-challenge".getBytes(StandardCharsets.UTF_8);
    byte[][] elements = {
      {0x02, 0x01, 0x00},
      {0x02, 0x01, 0x00},
      {0x02, 0x01, 0x00},
      {0x02, 0x01, 0x00},
      concat(new byte[] {0x04, (byte) challenge.length}, challenge),
    };
    int total = 0;
    for (byte[] e : elements) total += e.length;
    byte[] content = new byte[total];
    int off = 0;
    for (byte[] e : elements) {
      System.arraycopy(e, 0, content, off, e.length);
      off += e.length;
    }
    byte[] seq = concat(new byte[] {0x30, (byte) total}, content);
    assertThat(DerUtil.extractAndroidKeyAttestationChallenge(seq)).isEqualTo(challenge);
  }

  @Test
  void extract_android_key_challenge_rejects_sequence_with_fewer_than_5_elements() {
    byte[] seq = {0x30, 0x03, 0x02, 0x01, 0x00};
    assertThatThrownBy(() -> DerUtil.extractAndroidKeyAttestationChallenge(seq))
        .isInstanceOf(Fido2VerificationException.class)
        .hasMessageContaining("fewer than 5");
  }

  @Test
  void extract_android_key_challenge_element4_supports_0x82_length_encoding() throws Exception {
    // The SEQUENCE walker inside extractAndroidKeyAttestationChallenge supports 0x82 long-form for
    // individual elements. Build a SEQUENCE whose total size stays ≤ 255 bytes (short-form outer)
    // but whose 5th element (index 4, the challenge OCTET STRING) uses 0x82 length encoding.
    // We use a 40-byte challenge to keep total size under 255 bytes.
    byte[] challenge = new byte[40];
    for (int i = 0; i < challenge.length; i++) challenge[i] = (byte) (i & 0xff);

    // Build 5 elements: 4 small INTEGERs + 1 OCTET STRING (challenge) with 0x82 length
    byte[][] elements = {
      {0x02, 0x01, 0x00},
      {0x02, 0x01, 0x00},
      {0x02, 0x01, 0x00},
      {0x02, 0x01, 0x00},
      concat(
          new byte[] {0x04, (byte) 0x82, 0x00, (byte) challenge.length},
          challenge), // OCTET STRING with 0x82 length
    };

    int total = 0;
    for (byte[] e : elements) total += e.length;
    byte[] content = new byte[total];
    int off = 0;
    for (byte[] e : elements) {
      System.arraycopy(e, 0, content, off, e.length);
      off += e.length;
    }
    // Outer SEQUENCE uses short-form length (total fits in one byte here)
    byte[] seq = concat(new byte[] {0x30, (byte) total}, content);
    assertThat(DerUtil.extractAndroidKeyAttestationChallenge(seq)).isEqualTo(challenge);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
