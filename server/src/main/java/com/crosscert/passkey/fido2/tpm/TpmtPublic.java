package com.crosscert.passkey.fido2.tpm;

import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * The TPM 2.0 {@code TPMT_PUBLIC} structure parsed from the {@code pubArea} field of a TPM
 * attestation statement. Only the {@code RSA} (0x0001) and {@code ECC} (0x0023) algorithm types are
 * supported — those are the only ones in use by WebAuthn tpm authenticators.
 *
 * <p>Spec: TCG TPM 2.0 Library Part 2 §12.2.4.
 */
public record TpmtPublic(int type, int nameAlg, PublicKey publicKey) {

  public static final int TPM_ALG_RSA = 0x0001;
  public static final int TPM_ALG_ECC = 0x0023;

  public static TpmtPublic parse(byte[] raw) {
    try {
      ByteBuffer buf = ByteBuffer.wrap(raw);
      int type = Short.toUnsignedInt(buf.getShort());
      int nameAlg = Short.toUnsignedInt(buf.getShort());
      buf.getInt(); // objectAttributes — not validated here
      skipSized(buf, "authPolicy");
      PublicKey publicKey =
          switch (type) {
            case TPM_ALG_RSA -> parseRsaParametersAndUnique(buf);
            case TPM_ALG_ECC -> parseEccParametersAndUnique(buf);
            default ->
                throw new TpmException(
                    "TPMT_PUBLIC unsupported type 0x" + Integer.toHexString(type));
          };
      if (buf.hasRemaining()) {
        throw new TpmException("TPMT_PUBLIC has " + buf.remaining() + " trailing bytes");
      }
      return new TpmtPublic(type, nameAlg, publicKey);
    } catch (BufferUnderflowException e) {
      throw new TpmException("TPMT_PUBLIC truncated", e);
    }
  }

  private static PublicKey parseRsaParametersAndUnique(ByteBuffer buf) {
    buf.getShort(); // symmetric — skipped
    buf.getShort(); // scheme — skipped
    int keyBits = Short.toUnsignedInt(buf.getShort());
    long exponent = Integer.toUnsignedLong(buf.getInt());
    if (exponent == 0L) {
      exponent = 65537L; // TPM spec: 0 means "use the default public exponent of 65537".
    }
    byte[] modulus = readSized(buf, "RSA modulus");
    if (modulus.length * 8 != keyBits) {
      throw new TpmException(
          "TPMT_PUBLIC RSA modulus length ("
              + (modulus.length * 8)
              + " bits) != keyBits "
              + keyBits);
    }
    try {
      RSAPublicKeySpec spec =
          new RSAPublicKeySpec(new BigInteger(1, modulus), BigInteger.valueOf(exponent));
      return KeyFactory.getInstance("RSA").generatePublic(spec);
    } catch (Exception e) {
      throw new TpmException("TPMT_PUBLIC RSA key reconstruction failed", e);
    }
  }

  private static PublicKey parseEccParametersAndUnique(ByteBuffer buf) {
    buf.getShort(); // symmetric — skipped
    buf.getShort(); // scheme — skipped
    int curveId = Short.toUnsignedInt(buf.getShort());
    buf.getShort(); // kdf — skipped
    // TPM_ECC_NIST_P256 = 0x0003 — the only curve WebAuthn tpm uses in practice.
    if (curveId != 0x0003) {
      throw new TpmException("TPMT_PUBLIC ECC unsupported curve 0x" + Integer.toHexString(curveId));
    }
    byte[] x = readSized(buf, "ECC x");
    byte[] y = readSized(buf, "ECC y");
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
      ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
      return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, ecSpec));
    } catch (Exception e) {
      throw new TpmException("TPMT_PUBLIC ECC key reconstruction failed", e);
    }
  }

  private static byte[] readSized(ByteBuffer buf, String fieldName) {
    if (buf.remaining() < 2) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " length prefix truncated");
    }
    int len = Short.toUnsignedInt(buf.getShort());
    if (buf.remaining() < len) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " truncated");
    }
    byte[] out = new byte[len];
    buf.get(out);
    return out;
  }

  private static void skipSized(ByteBuffer buf, String fieldName) {
    if (buf.remaining() < 2) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " length prefix truncated");
    }
    int len = Short.toUnsignedInt(buf.getShort());
    if (buf.remaining() < len) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " truncated");
    }
    buf.position(buf.position() + len);
  }
}
