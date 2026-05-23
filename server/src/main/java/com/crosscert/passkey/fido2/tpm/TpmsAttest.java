package com.crosscert.passkey.fido2.tpm;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * The TPM 2.0 {@code TPMS_ATTEST} structure parsed from the {@code certInfo} field of a TPM
 * attestation statement. Only {@code TPM_ST_ATTEST_CERTIFY} (0x8017) is supported — that is the
 * only attest type WebAuthn's tpm format uses.
 *
 * <p>Spec: TCG TPM 2.0 Library Part 2 §10.12, §10.13. Field layout:
 *
 * <pre>
 *   TPM_GENERATED magic           (4B big-endian, must equal 0xFF544347 == "\xFFTCG")
 *   TPMI_ST_ATTEST type           (2B BE, must equal 0x8017 == TPM_ST_ATTEST_CERTIFY)
 *   TPM2B_NAME qualifiedSigner    (2B BE length || bytes)
 *   TPM2B_DATA extraData          (2B BE length || bytes)
 *   TPMS_CLOCK_INFO clockInfo     (17B — opaque to us)
 *   UINT64 firmwareVersion        (8B BE — opaque)
 *   TPMS_CERTIFY_INFO attested    (TPM2B_NAME name || TPM2B_NAME qualifiedName)
 * </pre>
 */
public record TpmsAttest(
    int magic,
    int type,
    byte[] qualifiedSigner,
    byte[] extraData,
    long firmwareVersion,
    byte[] attestedName,
    byte[] attestedQualifiedName) {

  public static final int TPM_GENERATED_VALUE = 0xFF544347;
  public static final int TPM_ST_ATTEST_CERTIFY = 0x8017;

  public static TpmsAttest parse(byte[] raw) {
    try {
      ByteBuffer buf = ByteBuffer.wrap(raw); // big-endian by default
      int magic = buf.getInt();
      if (magic != TPM_GENERATED_VALUE) {
        throw new TpmException(
            "TPMS_ATTEST magic is not TPM_GENERATED_VALUE (got 0x"
                + Integer.toHexString(magic)
                + ")");
      }
      int type = Short.toUnsignedInt(buf.getShort());
      if (type != TPM_ST_ATTEST_CERTIFY) {
        throw new TpmException(
            "TPMS_ATTEST type is not TPM_ST_ATTEST_CERTIFY (got 0x"
                + Integer.toHexString(type)
                + ")");
      }
      byte[] qualifiedSigner = readSized(buf, "qualifiedSigner");
      byte[] extraData = readSized(buf, "extraData");
      // Skip clockInfo (17 bytes: UINT64 clock + UINT32 resetCount + UINT32 restartCount + UINT8
      // safe).
      if (buf.remaining() < 17) {
        throw new TpmException("TPMS_ATTEST clockInfo truncated");
      }
      buf.position(buf.position() + 17);
      long firmwareVersion = buf.getLong();
      byte[] attestedName = readSized(buf, "attestedName");
      byte[] attestedQualifiedName = readSized(buf, "attestedQualifiedName");
      if (buf.hasRemaining()) {
        throw new TpmException(
            "TPMS_ATTEST has " + buf.remaining() + " trailing bytes — malformed");
      }
      return new TpmsAttest(
          magic,
          type,
          qualifiedSigner,
          extraData,
          firmwareVersion,
          attestedName,
          attestedQualifiedName);
    } catch (BufferUnderflowException e) {
      throw new TpmException("TPMS_ATTEST truncated", e);
    }
  }

  private static byte[] readSized(ByteBuffer buf, String fieldName) {
    if (buf.remaining() < 2) {
      throw new TpmException("TPMS_ATTEST " + fieldName + " length prefix truncated");
    }
    int len = Short.toUnsignedInt(buf.getShort());
    if (buf.remaining() < len) {
      throw new TpmException(
          "TPMS_ATTEST "
              + fieldName
              + " truncated (declared "
              + len
              + ", remaining "
              + buf.remaining()
              + ")");
    }
    byte[] out = new byte[len];
    buf.get(out);
    return out;
  }
}
