package com.crosscert.passkey.fido2.tpm;

/**
 * TPM 2.0 structure parsing/consistency failure. Unchecked — the verifier wraps it in {@code
 * Fido2VerificationException(INVALID_TPM_STRUCTURE)} so the boundary contract (the {@code fido2}
 * core throws only {@code Fido2VerificationException}) is preserved.
 */
public class TpmException extends RuntimeException {
  public TpmException(String message) {
    super(message);
  }

  public TpmException(String message, Throwable cause) {
    super(message, cause);
  }
}
