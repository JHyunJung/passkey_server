package com.crosscert.passkey.ratelimit;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/**
 * Fixed-window counter. Each (key, minute) bucket increments; the first INCR sets a 75s TTL
 * atomically in the same Lua call. Simpler than sliding-window — accuracy at the boundary is fine
 * for abuse prevention. Lua keeps INCR+EXPIRE in a single round-trip.
 */
@Component
@RequiredArgsConstructor
public class RateLimiter {

  private static final String NS = "passkey:ratelimit";
  private static final String TTL_SECONDS = "75";

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
    long minute = System.currentTimeMillis() / 60_000;
    String key = NS + ":" + bucket + ":" + minute;
    Long count = redis.execute(INCR_SCRIPT, List.of(key), TTL_SECONDS);
    return count != null && count <= limitPerMinute;
  }
}
