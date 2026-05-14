package com.crosscert.passkey.credential.challenge;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis-backed challenge store. Keys are scoped per-tenant + per-ceremony-id. TTL of 5 minutes
 * matches typical authenticator UX timeouts.
 */
@Component
@RequiredArgsConstructor
public class ChallengeStore {

  private static final Duration TTL = Duration.ofMinutes(5);
  private static final String KEY_PREFIX = "passkey:challenge";

  /** Lua: atomic GET+DEL. Returns the previous value or nil. Closes the replay window. */
  private static final DefaultRedisScript<String> CONSUME_SCRIPT =
      new DefaultRedisScript<>(
          "local v = redis.call('GET', KEYS[1]); "
              + "if v then redis.call('DEL', KEYS[1]); end; "
              + "return v",
          String.class);

  private final StringRedisTemplate redis;
  private final ObjectMapper objectMapper;

  /** Returns the ceremony id used to look the challenge up on the next request. */
  public UUID save(ChallengeRecord record) {
    UUID ceremonyId = UUID.randomUUID();
    String key = buildKey(record.tenantId(), ceremonyId);
    try {
      redis.opsForValue().set(key, objectMapper.writeValueAsString(record), TTL);
    } catch (JsonProcessingException e) {
      throw new BusinessException(
          ErrorCode.INTERNAL_SERVER_ERROR, "failed to serialise challenge record", e);
    }
    return ceremonyId;
  }

  public Optional<ChallengeRecord> consume(UUID ceremonyId) {
    UUID tenantId = TenantContextHolder.required().tenantId();
    String key = buildKey(tenantId, ceremonyId);
    String json = redis.execute(CONSUME_SCRIPT, List.of(key));
    if (json == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(objectMapper.readValue(json, ChallengeRecord.class));
    } catch (JsonProcessingException e) {
      throw new BusinessException(
          ErrorCode.INTERNAL_SERVER_ERROR, "failed to deserialise challenge record", e);
    }
  }

  private String buildKey(UUID tenantId, UUID ceremonyId) {
    return KEY_PREFIX + ":" + tenantId + ":" + ceremonyId;
  }
}
