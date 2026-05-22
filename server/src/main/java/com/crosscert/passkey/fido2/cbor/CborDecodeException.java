package com.crosscert.passkey.fido2.cbor;

/**
 * Thrown when a byte sequence is not valid CBOR within the WebAuthn-required subset (RFC 8949 major
 * types 0-5 and the false/true/null simple values). Unchecked — callers in the {@code fido2}
 * package translate it into a {@code Fido2VerificationException} with {@code MALFORMED_CBOR}.
 */
public class CborDecodeException extends RuntimeException {
  public CborDecodeException(String message) {
    super(message);
  }
}
