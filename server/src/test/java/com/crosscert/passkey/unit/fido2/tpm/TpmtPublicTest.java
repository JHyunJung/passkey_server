package com.crosscert.passkey.unit.fido2.tpm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.tpm.TpmException;
import com.crosscert.passkey.fido2.tpm.TpmtPublic;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class TpmtPublicTest {

  @Test
  void parses_rsa_2048_public_area_and_reconstructs_key() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair pair = gen.generateKeyPair();
    RSAPublicKey expected = (RSAPublicKey) pair.getPublic();

    byte[] modulus = unsignedBytes(expected.getModulus(), 256);
    byte[] pubArea = TpmFixtures.publicRsa2048(modulus);

    TpmtPublic pub = TpmtPublic.parse(pubArea);
    assertThat(pub.type()).isEqualTo(0x0001);
    assertThat(pub.nameAlg()).isEqualTo(0x000B);
    RSAPublicKey reconstructed = (RSAPublicKey) pub.publicKey();
    assertThat(reconstructed.getModulus()).isEqualTo(expected.getModulus());
    assertThat(reconstructed.getPublicExponent()).isEqualTo(BigInteger.valueOf(65537));
  }

  @Test
  void rejects_unknown_alg_type() {
    byte[] pubArea = TpmFixtures.publicRsa2048(new byte[256]);
    pubArea[0] = 0x00;
    pubArea[1] = 0x10; // unknown alg
    assertThatThrownBy(() -> TpmtPublic.parse(pubArea))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("unsupported");
  }

  // ---- Extra negative tests for fail-closed coverage ----

  @Test
  void rejects_modulus_keybits_mismatch() {
    // keyBits field says 2048 but modulus is only 128 bytes (1024 bits).
    byte[] shortModulus = new byte[128];
    byte[] pubArea = TpmFixtures.publicRsa2048(shortModulus);
    // The fixture hard-codes keyBits=2048 (bytes 10-11 = 0x0800).
    // The modulus length field will be 128, causing 128*8=1024 != 2048 mismatch.
    assertThatThrownBy(() -> TpmtPublic.parse(pubArea))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("keyBits");
  }

  @Test
  void rejects_trailing_bytes() {
    KeyPairGenerator gen;
    try {
      gen = KeyPairGenerator.getInstance("RSA");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    gen.initialize(2048);
    RSAPublicKey pub = (RSAPublicKey) gen.generateKeyPair().getPublic();
    byte[] modulus = unsignedBytes(pub.getModulus(), 256);
    byte[] pubArea = TpmFixtures.publicRsa2048(modulus);
    byte[] extended = Arrays.copyOf(pubArea, pubArea.length + 1);
    extended[pubArea.length] = (byte) 0xAB;
    assertThatThrownBy(() -> TpmtPublic.parse(extended))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("trailing bytes");
  }

  private static byte[] unsignedBytes(BigInteger n, int len) {
    byte[] raw = n.toByteArray();
    if (raw.length == len) return raw;
    if (raw.length == len + 1 && raw[0] == 0) {
      byte[] out = new byte[len];
      System.arraycopy(raw, 1, out, 0, len);
      return out;
    }
    if (raw.length < len) {
      byte[] out = new byte[len];
      System.arraycopy(raw, 0, out, len - raw.length, raw.length);
      return out;
    }
    throw new IllegalArgumentException("too large");
  }
}
