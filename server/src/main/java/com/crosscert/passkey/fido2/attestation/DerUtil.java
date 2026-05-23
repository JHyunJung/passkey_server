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
   * Extract the {@code attestationChallenge} from an Android Key Attestation extension's {@code
   * KeyDescription} SEQUENCE. The challenge is the fifth element (zero-based index 4) of the
   * SEQUENCE — an {@code OCTET STRING} per the Android Keystore key attestation specification.
   *
   * <p>Input is the {@code KeyDescription} SEQUENCE itself ({@link
   * java.security.cert.X509Certificate#getExtensionValue} returns the extension wrapped in an outer
   * {@code OCTET STRING} which the caller unwraps via {@link #unwrapOctetString} first).
   *
   * <p>Element length encoding up to {@code 0x82} (two-byte long-form) is supported inside the
   * SEQUENCE walk, because {@code softwareEnforced} / {@code teeEnforced} AuthorizationList values
   * can exceed 255 bytes.
   */
  public static byte[] extractAndroidKeyAttestationChallenge(byte[] keyDescriptionDer)
      throws Fido2VerificationException {
    byte[] sequenceContent = unwrapTag(keyDescriptionDer, TAG_SEQUENCE, "KeyDescription SEQUENCE");
    int pos = 0;
    int index = 0;
    while (pos < sequenceContent.length) {
      if (pos + 2 > sequenceContent.length) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "KeyDescription SEQUENCE truncated at element " + index);
      }
      int tag = sequenceContent[pos] & 0xff;
      int lengthByte = sequenceContent[pos + 1] & 0xff;
      int headerLen;
      int contentLen;
      if (lengthByte < 0x80) {
        headerLen = 2;
        contentLen = lengthByte;
      } else if (lengthByte == 0x81) {
        if (pos + 3 > sequenceContent.length) {
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID,
              "KeyDescription element length truncated at index " + index);
        }
        headerLen = 3;
        contentLen = sequenceContent[pos + 2] & 0xff;
      } else if (lengthByte == 0x82) {
        if (pos + 4 > sequenceContent.length) {
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID,
              "KeyDescription element length truncated at index " + index);
        }
        headerLen = 4;
        contentLen = ((sequenceContent[pos + 2] & 0xff) << 8) | (sequenceContent[pos + 3] & 0xff);
      } else {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "KeyDescription element has unsupported length encoding at index " + index);
      }
      int nextPos = pos + headerLen + contentLen;
      if (nextPos > sequenceContent.length) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "KeyDescription element extends past SEQUENCE at index " + index);
      }
      if (index == 4) {
        // Index 4 must be an OCTET STRING (attestationChallenge).
        if (tag != TAG_OCTET_STRING) {
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID,
              "KeyDescription[4] is not an OCTET STRING (tag 0x" + Integer.toHexString(tag) + ")");
        }
        return Arrays.copyOfRange(sequenceContent, pos + headerLen, nextPos);
      }
      pos = nextPos;
      index++;
    }
    throw new Fido2VerificationException(
        FailureReason.ATTESTATION_INVALID,
        "KeyDescription SEQUENCE has fewer than 5 elements (got " + index + ")");
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
