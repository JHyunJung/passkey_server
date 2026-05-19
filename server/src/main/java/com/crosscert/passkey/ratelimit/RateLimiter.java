package com.crosscert.passkey.ratelimit;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/**
 * Fixed-window counter. Each (key, minute) bucket increments; the first INCR sets the TTL
 * atomically in the same Lua call. Simpler than sliding-window — accuracy at the boundary is fine
 * for abuse prevention. Lua keeps INCR+EXPIRE in a single round-trip.
 */
@Component
@RequiredArgsConstructor
public class RateLimiter {

  private static final String NS = "passkey:ratelimit";
  private static final long WINDOW_SECONDS = 60L;
  // Safety margin keeps the bucket alive a bit past its window so a burst that lands exactly on
  // the minute boundary still observes the previous bucket's tail. 15s is enough at our scale.
  private static final long BUCKET_TTL_SAFETY_MARGIN_SECONDS = 15L;
  private static final String BUCKET_TTL_SECONDS =
      Long.toString(WINDOW_SECONDS + BUCKET_TTL_SAFETY_MARGIN_SECONDS);

  /** Lua: atomic INCR + (EXPIRE on first increment). Returns the new counter value. */
  private static final DefaultRedisScript<Long> INCR_SCRIPT =
      new DefaultRedisScript<>(
          "local n = redis.call('INCR', KEYS[1]); "
              + "if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; "
              + "return n",
          Long.class);

  private final StringRedisTemplate redis;

  /** Returns {@code true} when the request is within the limit. */
  public boolean tryAcquire(String bucket, int limitPerMinute) {
    long minute = System.currentTimeMillis() / (WINDOW_SECONDS * 1000L);
    String key = NS + ":" + bucket + ":" + minute;
    Long count = redis.execute(INCR_SCRIPT, List.of(key), BUCKET_TTL_SECONDS);
    return count != null && count <= limitPerMinute;
  }
}
