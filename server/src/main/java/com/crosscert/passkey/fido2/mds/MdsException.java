package com.crosscert.passkey.fido2.mds;

/**
 * Thrown when a FIDO MDS3 metadata BLOB cannot be parsed or fails verification — a malformed JWS, a
 * bad payload, or a trust-chain failure on the BLOB's signing certificate. Unchecked; callers in
 * the {@code fido2} package translate it into a {@code Fido2VerificationException} or surface it as
 * an MDS-unavailable condition.
 */
public class MdsException extends RuntimeException {
  public MdsException(String message) {
    super(message);
  }

  public MdsException(String message, Throwable cause) {
    super(message, cause);
  }
}
