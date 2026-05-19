package com.crosscert.passkey.rp.error;

import java.time.Duration;

/**
 * R001 — server's per-tenant rate limit hit. {@link #retryAfter()} echoes the server's {@code
 * Retry-After} header (or null if the server did not provide one). The HTTP layer retries
 * automatically up to {@code max-retries}; this exception only surfaces when retries are exhausted.
 */
public class PasskeyRateLimitException extends PasskeyApiException {

  private final Duration retryAfter;

  public PasskeyRateLimitException(
      String rawCode, int httpStatus, String message, String traceId, Duration retryAfter) {
    super(ErrorCode.RATE_LIMIT_EXCEEDED, rawCode, httpStatus, message, traceId);
    this.retryAfter = retryAfter;
  }

  public Duration retryAfter() {
    return retryAfter;
  }
}
