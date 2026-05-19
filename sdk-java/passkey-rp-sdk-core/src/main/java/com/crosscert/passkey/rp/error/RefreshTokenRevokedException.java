package com.crosscert.passkey.rp.error;

/** A011 — refresh token already revoked. RP should clear the cookie and force re-login. */
public class RefreshTokenRevokedException extends PasskeyApiException {
  public RefreshTokenRevokedException(
      String rawCode, int httpStatus, String message, String traceId) {
    super(ErrorCode.REFRESH_TOKEN_REVOKED, rawCode, httpStatus, message, traceId);
  }
}
