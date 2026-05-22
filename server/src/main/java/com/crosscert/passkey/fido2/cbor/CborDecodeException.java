package com.crosscert.passkey.fido2.cbor;

/**
 * Thrown when input the {@code fido2} core decodes is malformed — CBOR outside the
 * WebAuthn-required subset (RFC 8949 major types 0-5 and the false/true/null simple values), or
 * clientDataJSON that is not well-formed JSON with the expected fields. Unchecked — callers in the
 * {@code fido2} package translate it into a {@code Fido2VerificationException} with {@code
 * MALFORMED_CBOR} / {@code MALFORMED_CLIENT_DATA}.
 */
public class CborDecodeException extends RuntimeException {
  public CborDecodeException(String message) {
    super(message);
  }

  public CborDecodeException(String message, Throwable cause) {
    super(message, cause);
  }
}
