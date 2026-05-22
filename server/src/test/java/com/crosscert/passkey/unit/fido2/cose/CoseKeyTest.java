package com.crosscert.passkey.unit.fido2.cose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CoseKeyTest {

  @Test
  void parses_es256_key_and_verifies_signature() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = gen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) pair.getPublic();

    byte[] coseBytes = es256CoseKey(pub);
    CoseKey key = CoseKey.parse(coseBytes);
    assertThat(key.algorithm()).isEqualTo(-7L);

    byte[] message = "fido2-core".getBytes();
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(pair.getPrivate());
    signer.update(message);
    byte[] sig = signer.sign();

    assertThat(CoseSignatureVerifier.verify(key, message, sig)).isTrue();
    assertThat(CoseSignatureVerifier.verify(key, "tampered".getBytes(), sig)).isFalse();
  }

  @Test
  void parses_rs256_key_and_verifies_signature() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048, new SecureRandom());
    KeyPair pair = gen.generateKeyPair();
    java.security.interfaces.RSAPublicKey pub =
        (java.security.interfaces.RSAPublicKey) pair.getPublic();

    byte[] coseBytes = rs256CoseKey(pub);
    CoseKey key = CoseKey.parse(coseBytes);
    assertThat(key.algorithm()).isEqualTo(-257L);

    byte[] message = "fido2-core".getBytes();
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(pair.getPrivate());
    signer.update(message);
    byte[] sig = signer.sign();

    assertThat(CoseSignatureVerifier.verify(key, message, sig)).isTrue();
  }

  @Test
  void rejects_unsupported_algorithm() {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 1L); // kty: OKP
    m.put(3L, -8L); // alg: EdDSA — Milestone A 범위 밖
    byte[] cbor = com.crosscert.passkey.unit.fido2.CborTestEncoder.encodeMap(m);
    assertThatThrownBy(() -> CoseKey.parse(cbor)).isInstanceOf(CoseException.class);
  }

  // COSE_Key for EC2/ES256: {1:2, 3:-7, -1:1, -2:x, -3:y}
  private static byte[] es256CoseKey(ECPublicKey pub) {
    byte[] x = unsignedFixed(pub.getW().getAffineX(), 32);
    byte[] y = unsignedFixed(pub.getW().getAffineY(), 32);
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L);
    m.put(3L, -7L);
    m.put(-1L, 1L);
    m.put(-2L, x);
    m.put(-3L, y);
    return com.crosscert.passkey.unit.fido2.CborTestEncoder.encodeMap(m);
  }

  // COSE_Key for RSA/RS256: {1:3, 3:-257, -1:n, -2:e}
  private static byte[] rs256CoseKey(java.security.interfaces.RSAPublicKey pub) {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 3L);
    m.put(3L, -257L);
    m.put(-1L, toUnsigned(pub.getModulus()));
    m.put(-2L, toUnsigned(pub.getPublicExponent()));
    return com.crosscert.passkey.unit.fido2.CborTestEncoder.encodeMap(m);
  }

  private static byte[] unsignedFixed(java.math.BigInteger v, int len) {
    byte[] raw = toUnsigned(v);
    if (raw.length == len) {
      return raw;
    }
    byte[] out = new byte[len];
    System.arraycopy(
        raw,
        Math.max(0, raw.length - len),
        out,
        Math.max(0, len - raw.length),
        Math.min(raw.length, len));
    return out;
  }

  private static byte[] toUnsigned(java.math.BigInteger v) {
    byte[] raw = v.toByteArray();
    if (raw.length > 1 && raw[0] == 0) {
      byte[] trimmed = new byte[raw.length - 1];
      System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
      return trimmed;
    }
    return raw;
  }
}
