package com.crosscert.passkey.fido2.cose;

/**
 * Thrown when a COSE_Key cannot be parsed or uses an algorithm outside the supported set (ES256 /
 * RS256 for Milestone A). Unchecked — translated to {@code UNSUPPORTED_ALGORITHM} or {@code
 * MALFORMED_CBOR} by the verifier layer.
 */
public class CoseException extends RuntimeException {
  public CoseException(String message) {
    super(message);
  }

  public CoseException(String message, Throwable cause) {
    super(message, cause);
  }
}
