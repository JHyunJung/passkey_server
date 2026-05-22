package com.crosscert.passkey.unit.fido2.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.model.CollectedClientData;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CollectedClientDataTest {

  @Test
  void parses_client_data_json() {
    String json =
        "{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\","
            + "\"origin\":\"https://example.com\",\"crossOrigin\":false}";
    CollectedClientData cd = CollectedClientData.parse(json.getBytes(StandardCharsets.UTF_8));
    assertThat(cd.type()).isEqualTo("webauthn.create");
    assertThat(cd.challenge()).isEqualTo("Y2hhbGxlbmdl");
    assertThat(cd.origin()).isEqualTo("https://example.com");
    assertThat(cd.crossOrigin()).isFalse();
  }

  @Test
  void tolerates_missing_cross_origin() {
    String json = "{\"type\":\"webauthn.get\",\"challenge\":\"YWJj\",\"origin\":\"https://a.com\"}";
    CollectedClientData cd = CollectedClientData.parse(json.getBytes(StandardCharsets.UTF_8));
    assertThat(cd.crossOrigin()).isFalse();
  }

  @Test
  void rejects_malformed_json() {
    assertThatThrownBy(() -> CollectedClientData.parse("not json".getBytes()))
        .isInstanceOf(CborDecodeException.class);
  }
}
