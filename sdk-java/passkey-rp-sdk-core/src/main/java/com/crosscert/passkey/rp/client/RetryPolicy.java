package com.crosscert.passkey.rp.client;

import java.time.Duration;
import java.util.Random;

/**
 * Retry policy used by {@link JdkPasskeyHttpClient}.
 *
 * <ul>
 *   <li>HTTP 429 → honour {@code Retry-After} (seconds-only; HTTP-date variant is uncommon for
 *       rate-limit responses and falls back to backoff).
 *   <li>HTTP 5xx → exponential backoff with ±20% jitter, capped at {@link #maxRetries()}.
 *   <li>HTTP 4xx (other) → no retry.
 *   <li>IOException / read timeout → retried with backoff.
 * </ul>
 */
public record RetryPolicy(int maxRetries, Duration baseBackoff) {

  public static RetryPolicy defaults() {
    return new RetryPolicy(3, Duration.ofMillis(200));
  }

  public Duration backoffFor(int attempt, Random rng) {
    long base = baseBackoff.toMillis() * (long) Math.pow(3, attempt);
    long jitter = (long) (base * 0.2 * (rng.nextDouble() - 0.5));
    return Duration.ofMillis(Math.max(base + jitter, 0L));
  }
}
