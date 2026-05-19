package com.crosscert.passkey.rp.error;

/** Parent for every {@code P###} (WebAuthn ceremony) error. */
public class PasskeyCeremonyException extends PasskeyApiException {
  public PasskeyCeremonyException(
      ErrorCode errorCode, String rawCode, int httpStatus, String message, String traceId) {
    super(errorCode, rawCode, httpStatus, message, traceId);
  }
}
