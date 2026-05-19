package com.crosscert.passkey.rp.error;

/**
 * Authentication-class errors (codes {@code A001}/{@code A002}/{@code A005}). The {@code expired}
 * flag is set for {@link ErrorCode#EXPIRED_TOKEN} so the @RestControllerAdvice can add a {@code
 * WWW-Authenticate: Bearer error=token_expired} header.
 */
public class PasskeyAuthenticationException extends PasskeyApiException {

  private final boolean expired;

  public PasskeyAuthenticationException(
      ErrorCode errorCode, String rawCode, int httpStatus, String message, String traceId) {
    super(errorCode, rawCode, httpStatus, message, traceId);
    this.expired = errorCode == ErrorCode.EXPIRED_TOKEN;
  }

  public boolean expired() {
    return expired;
  }
}
