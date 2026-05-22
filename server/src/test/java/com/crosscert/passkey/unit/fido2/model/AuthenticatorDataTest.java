package com.crosscert.passkey.unit.fido2.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.model.AuthenticatorData;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthenticatorDataTest {

  @Test
  void parses_authenticator_data_without_attested_credential() {
    // rpIdHash(32) + flags(1, UP only) + signCount(4) — no AT bit.
    byte[] rpIdHash = new byte[32];
    java.util.Arrays.fill(rpIdHash, (byte) 0xab);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(rpIdHash);
    out.write(0x01); // UP
    out.writeBytes(new byte[] {0, 0, 0, 5}); // signCount = 5

    AuthenticatorData ad = AuthenticatorData.parse(out.toByteArray());
    assertThat(ad.rpIdHash()).containsExactly(rpIdHash);
    assertThat(ad.flags().userPresent()).isTrue();
    assertThat(ad.flags().userVerified()).isFalse();
    assertThat(ad.flags().attestedCredentialDataIncluded()).isFalse();
    assertThat(ad.signCount()).isEqualTo(5L);
    assertThat(ad.attestedCredentialData()).isNull();
  }

  @Test
  void parses_authenticator_data_with_attested_credential() {
    byte[] coseKey = sampleCoseKey();
    byte[] aaguid = new byte[16];
    java.util.Arrays.fill(aaguid, (byte) 0x11);
    byte[] credId = new byte[] {1, 2, 3, 4};

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(new byte[32]); // rpIdHash
    out.write(0x45); // UP(0x01) | UV(0x04) | AT(0x40)
    out.writeBytes(new byte[] {0, 0, 0, 0}); // signCount
    out.writeBytes(aaguid);
    out.writeBytes(new byte[] {0, 4}); // credentialId length = 4
    out.writeBytes(credId);
    out.writeBytes(coseKey);

    AuthenticatorData ad = AuthenticatorData.parse(out.toByteArray());
    assertThat(ad.flags().attestedCredentialDataIncluded()).isTrue();
    AttestedCredentialData acd = ad.attestedCredentialData();
    assertThat(acd.credentialId()).containsExactly(credId);
    assertThat(acd.aaguid()).containsExactly(aaguid);
    assertThat(acd.coseKey().algorithm()).isEqualTo(-7L);
  }

  @Test
  void attested_credential_data_round_trips_webauthn4j_serialized_form() {
    // webauthn4j AttestedCredentialDataConverter format: aaguid(16) + credIdLen(2) + credId + cose
    byte[] aaguid = new byte[16];
    byte[] credId = new byte[] {9, 8, 7};
    byte[] coseKey = sampleCoseKey();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(aaguid);
    out.writeBytes(new byte[] {0, 3});
    out.writeBytes(credId);
    out.writeBytes(coseKey);

    AttestedCredentialData acd = AttestedCredentialData.parse(out.toByteArray());
    assertThat(acd.credentialId()).containsExactly(credId);
    assertThat(acd.coseKey().algorithm()).isEqualTo(-7L);
  }

  @Test
  void rejects_truncated_authenticator_data() {
    assertThatThrownBy(() -> AuthenticatorData.parse(new byte[10]))
        .isInstanceOf(CborDecodeException.class);
  }

  private static byte[] sampleCoseKey() {
    // A real, on-curve ES256 COSE_Key — CoseKey.parse() validates the point lies on P-256.
    try {
      java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("EC");
      gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
      java.security.interfaces.ECPublicKey pub =
          (java.security.interfaces.ECPublicKey) gen.generateKeyPair().getPublic();
      Map<Object, Object> m = new LinkedHashMap<>();
      m.put(1L, 2L);
      m.put(3L, -7L);
      m.put(-1L, 1L);
      m.put(-2L, coordinate(pub.getW().getAffineX()));
      m.put(-3L, coordinate(pub.getW().getAffineY()));
      return CborTestEncoder.encodeMap(m);
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  // Fixed 32-byte big-endian encoding of an EC coordinate.
  private static byte[] coordinate(java.math.BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    if (raw.length > 32) {
      System.arraycopy(raw, raw.length - 32, out, 0, 32);
    } else {
      System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
    }
    return out;
  }
}
