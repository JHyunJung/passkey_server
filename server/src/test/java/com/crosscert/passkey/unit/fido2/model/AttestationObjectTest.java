package com.crosscert.passkey.unit.fido2.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AttestationObjectTest {

  @Test
  void parses_none_attestation_object() {
    byte[] authData = sampleAuthData();
    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "none");
    obj.put("attStmt", new LinkedHashMap<>());
    obj.put("authData", authData);

    AttestationObject parsed = AttestationObject.parse(CborTestEncoder.encodeMap(obj));
    assertThat(parsed.format()).isEqualTo("none");
    assertThat(parsed.attestationStatement()).isEmpty();
    assertThat(parsed.authenticatorData().rpIdHash()).hasSize(32);
  }

  private static byte[] sampleAuthData() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(new byte[32]); // rpIdHash
    out.write(0x01); // UP
    out.writeBytes(new byte[] {0, 0, 0, 1}); // signCount
    return out.toByteArray();
  }
}
