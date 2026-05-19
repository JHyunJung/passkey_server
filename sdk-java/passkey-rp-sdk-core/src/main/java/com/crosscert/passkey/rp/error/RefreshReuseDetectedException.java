package com.crosscert.passkey.rp.error;

/**
 * A012 — a previously-revoked refresh token was presented. The server burns the whole rotation
 * family in response. The RP MUST treat this as a hostile-take-over signal and force-logout the
 * user; the starter's advice adds {@code Clear-Site-Data: "cookies"} automatically.
 */
public class RefreshReuseDetectedException extends PasskeyApiException {
  public RefreshReuseDetectedException(
      String rawCode, int httpStatus, String message, String traceId) {
    super(ErrorCode.REFRESH_TOKEN_REUSED, rawCode, httpStatus, message, traceId);
  }
}
