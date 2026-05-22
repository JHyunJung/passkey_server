package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import java.util.Arrays;

/**
 * Minimal DER (ASN.1 Distinguished Encoding Rules) parsing helpers for attestation certificate
 * extensions. The {@code fido2} core deliberately avoids a full ASN.1 dependency — Apple anonymous
 * and FIDO AAGUID extensions both fit a tiny subset (single OCTET STRING wrapping or a SEQUENCE
 * holding a context-tagged OCTET STRING), and rolling a focused parser keeps the dependency surface
 * small. Anything outside the supported subset is rejected as malformed.
 */
public final class DerUtil {

  /** DER tag for OCTET STRING. */
  private static final int TAG_OCTET_STRING = 0x04;

  /** DER tag for SEQUENCE (constructed). */
  private static final int TAG_SEQUENCE = 0x30;

  /** Context-specific [1] EXPLICIT tag (constructed). */
  private static final int TAG_CONTEXT_1_EXPLICIT = 0xa1;

  private DerUtil() {}

  /**
   * Unwrap a single DER {@code OCTET STRING} (tag {@code 0x04}) and return its contents. Only the
   * short-form and the single-byte {@code 0x81} long-form length encodings are supported — enough
   * for the AAGUID and Apple nonce extensions; anything else is rejected as malformed.
   */
  public static byte[] unwrapOctetString(byte[] der, String what)
      throws Fido2VerificationException {
    return unwrapTag(der, TAG_OCTET_STRING, what);
  }

  /**
   * Extract the Apple anonymous attestation nonce. The Apple extension value (after the outer
   * {@code OCTET STRING} that {@link java.security.cert.X509Certificate#getExtensionValue} returns
   * has already been peeled off) is a {@code SEQUENCE} whose single element is a context-tagged
   * {@code [1] EXPLICIT} wrapping an {@code OCTET STRING} of the nonce — i.e. the SHA-256 of {@code
   * authenticatorData || clientDataHash}.
   */
  public static byte[] extractAppleNonce(byte[] sequenceContent) throws Fido2VerificationException {
    byte[] inSequence = unwrapTag(sequenceContent, TAG_SEQUENCE, "Apple nonce SEQUENCE");
    byte[] inContext1 = unwrapTag(inSequence, TAG_CONTEXT_1_EXPLICIT, "Apple nonce [1] EXPLICIT");
    return unwrapTag(inContext1, TAG_OCTET_STRING, "Apple nonce OCTET STRING");
  }

  /**
   * Unwrap a DER value of the given tag and return its contents. Supports short-form and the {@code
   * 0x81} long-form length encodings; rejects everything else (long-form {@code 0x82}+,
   * indefinite-length, trailing bytes) as malformed for fail-closed parsing.
   */
  private static byte[] unwrapTag(byte[] der, int expectedTag, String what)
      throws Fido2VerificationException {
    if (der == null || der.length < 2) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "malformed " + what + " (truncated)");
    }
    if ((der[0] & 0xff) != expectedTag) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "malformed "
              + what
              + " (unexpected tag 0x"
              + Integer.toHexString(der[0] & 0xff)
              + ", expected 0x"
              + Integer.toHexString(expectedTag)
              + ")");
    }
    int lengthByte = der[1] & 0xff;
    int contentOffset;
    int contentLength;
    if (lengthByte < 0x80) {
      contentOffset = 2;
      contentLength = lengthByte;
    } else if (lengthByte == 0x81) {
      if (der.length < 3) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "malformed " + what + " (truncated length)");
      }
      contentOffset = 3;
      contentLength = der[2] & 0xff;
    } else {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "malformed " + what + " (unsupported DER length encoding)");
    }
    if (contentOffset + contentLength != der.length) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "malformed " + what + " (length mismatch)");
    }
    return Arrays.copyOfRange(der, contentOffset, contentOffset + contentLength);
  }
}
