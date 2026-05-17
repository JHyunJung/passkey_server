package com.crosscert.passkey.unit.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.ratelimit.RateLimiter;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

/**
 * Verifies that {@link RateLimiter} dispatches the atomic Lua script (single round-trip
 * INCR+EXPIRE) and returns true/false based on the script's counter result.
 */
@ExtendWith(MockitoExtension.class)
class RateLimiterTest {

  @Mock private StringRedisTemplate redis;

  @Test
  @SuppressWarnings({"unchecked", "rawtypes"})
  void within_limit_returns_true() {
    when(redis.execute(any(RedisScript.class), any(List.class), anyString())).thenReturn(3L);
    RateLimiter limiter = new RateLimiter(redis);

    boolean accepted = limiter.tryAcquire("tenant-A:register", 10);

    assertThat(accepted).isTrue();
  }

  @Test
  @SuppressWarnings({"unchecked", "rawtypes"})
  void over_limit_returns_false() {
    when(redis.execute(any(RedisScript.class), any(List.class), anyString())).thenReturn(11L);
    RateLimiter limiter = new RateLimiter(redis);

    boolean accepted = limiter.tryAcquire("tenant-A:register", 10);

    assertThat(accepted).isFalse();
  }

  @Test
  @SuppressWarnings({"unchecked", "rawtypes"})
  void single_round_trip_via_script() {
    when(redis.execute(any(RedisScript.class), any(List.class), anyString())).thenReturn(1L);
    RateLimiter limiter = new RateLimiter(redis);

    limiter.tryAcquire("any-bucket", 5);

    // Only the script is invoked — no separate INCR or EXPIRE on opsForValue /
    // RedisTemplate#expire.
    verify(redis, times(1)).execute(any(RedisScript.class), any(List.class), anyString());
    ArgumentCaptor<RedisScript<?>> script = ArgumentCaptor.forClass(RedisScript.class);
    verify(redis).execute(script.capture(), any(List.class), anyString());
    assertThat(script.getValue().getScriptAsString()).contains("INCR").contains("EXPIRE");
  }
}
