package com.crosscert.passkey.rp.error;

/**
 * Wraps low-level transport failures: socket timeouts, TLS errors, DNS failures, server returning a
 * body that cannot be parsed as the expected envelope. Surfaces as HTTP 503 via the starter's
 * advice.
 */
public class PasskeyTransportException extends PasskeyApiException {

  public PasskeyTransportException(String message, Throwable cause) {
    super(ErrorCode.UNKNOWN, "TRANSPORT", 503, message, null, cause);
  }
}
