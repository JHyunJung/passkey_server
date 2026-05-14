package com.crosscert.passkey.credential.challenge;

import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.data.redis.core.StringRedisTemplate;
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

  private final StringRedisTemplate redis;
  private final ObjectMapper objectMapper;

  /** Returns the ceremony id used to look the challenge up on the next request. */
  @SneakyThrows
  public UUID save(ChallengeRecord record) {
    UUID ceremonyId = UUID.randomUUID();
    String key = buildKey(record.tenantId(), ceremonyId);
    redis.opsForValue().set(key, objectMapper.writeValueAsString(record), TTL);
    return ceremonyId;
  }

  @SneakyThrows
  public Optional<ChallengeRecord> consume(UUID ceremonyId) {
    UUID tenantId = TenantContextHolder.required().tenantId();
    String key = buildKey(tenantId, ceremonyId);
    String json = redis.opsForValue().get(key);
    if (json == null) {
      return Optional.empty();
    }
    redis.delete(key);
    return Optional.of(objectMapper.readValue(json, ChallengeRecord.class));
  }

  private String buildKey(UUID tenantId, UUID ceremonyId) {
    return KEY_PREFIX + ":" + tenantId + ":" + ceremonyId;
  }
}
