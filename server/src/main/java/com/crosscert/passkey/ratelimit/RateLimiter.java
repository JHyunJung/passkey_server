package com.crosscert.passkey.ratelimit;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Fixed-window counter. Each (key, minute) bucket increments; the first INCR sets a 60s TTL.
 * Simpler than sliding-window — accuracy at the boundary is fine for abuse prevention.
 */
@Component
@RequiredArgsConstructor
public class RateLimiter {

  private static final String NS = "passkey:ratelimit";

  private final StringRedisTemplate redis;

  /** Returns {@code true} when the request is within the limit. */
  public boolean tryAcquire(String bucket, int limitPerMinute) {
    long minute = System.currentTimeMillis() / 60_000;
    String key = NS + ":" + bucket + ":" + minute;
    Long count = redis.opsForValue().increment(key);
    if (count != null && count == 1L) {
      redis.expire(key, Duration.ofSeconds(75));
    }
    return count != null && count <= limitPerMinute;
  }
}
