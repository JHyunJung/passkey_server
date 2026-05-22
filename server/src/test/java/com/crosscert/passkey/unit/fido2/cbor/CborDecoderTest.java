package com.crosscert.passkey.unit.fido2.cbor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import com.crosscert.passkey.fido2.cbor.CborDecoder.DecodeResult;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CborDecoderTest {

  // RFC 8949 Appendix A 테스트 벡터.
  @Test
  void decodes_unsigned_integers() {
    assertThat(CborDecoder.decode(hex("00"))).isEqualTo(0L);
    assertThat(CborDecoder.decode(hex("17"))).isEqualTo(23L);
    assertThat(CborDecoder.decode(hex("1818"))).isEqualTo(24L);
    assertThat(CborDecoder.decode(hex("190100"))).isEqualTo(256L);
    assertThat(CborDecoder.decode(hex("1a000f4240"))).isEqualTo(1000000L);
    assertThat(CborDecoder.decode(hex("1b0000000100000000"))).isEqualTo(4294967296L);
  }

  @Test
  void decodes_negative_integers() {
    assertThat(CborDecoder.decode(hex("20"))).isEqualTo(-1L);
    assertThat(CborDecoder.decode(hex("3863"))).isEqualTo(-100L);
    assertThat(CborDecoder.decode(hex("3903e7"))).isEqualTo(-1000L);
  }

  @Test
  void decodes_byte_and_text_strings() {
    assertThat((byte[]) CborDecoder.decode(hex("4401020304"))).containsExactly(1, 2, 3, 4);
    assertThat(CborDecoder.decode(hex("6161"))).isEqualTo("a");
    assertThat(CborDecoder.decode(hex("6449455446"))).isEqualTo("IETF");
  }

  @Test
  void decodes_arrays_and_maps() {
    assertThat(CborDecoder.decode(hex("83010203"))).isEqualTo(List.of(1L, 2L, 3L));
    assertThat(CborDecoder.decode(hex("a201020304"))).isEqualTo(Map.of(1L, 2L, 3L, 4L));
    // {"a": 1, "b": [2, 3]}
    assertThat(CborDecoder.decode(hex("a26161016162820203")))
        .isEqualTo(Map.of("a", 1L, "b", List.of(2L, 3L)));
  }

  @Test
  void decodes_simple_values() {
    assertThat(CborDecoder.decode(hex("f4"))).isEqualTo(false);
    assertThat(CborDecoder.decode(hex("f5"))).isEqualTo(true);
    assertThat(CborDecoder.decode(hex("f6"))).isNull();
  }

  @Test
  void reports_consumed_byte_count_for_trailing_data() {
    // attestationObject 패턴: CBOR map 뒤에 추가 바이트가 붙을 수 있음.
    byte[] input = hex("83010203" + "ffff");
    DecodeResult result = CborDecoder.decodeWithLength(input);
    assertThat(result.value()).isEqualTo(List.of(1L, 2L, 3L));
    assertThat(result.consumed()).isEqualTo(4);
  }

  @Test
  void rejects_truncated_input() {
    assertThatThrownBy(() -> CborDecoder.decode(hex("19ff")))
        .isInstanceOf(CborDecodeException.class);
  }

  @Test
  void rejects_unsupported_major_type() {
    // major type 6 (tag) — WebAuthn subset 밖.
    assertThatThrownBy(() -> CborDecoder.decode(hex("c074")))
        .isInstanceOf(CborDecodeException.class);
  }

  private static byte[] hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
}
