package com.crosscert.passkey.auth.apikey.cache;

import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/** Publishes API-key revocation events so other JVM instances can evict their verify caches. */
@Component
@RequiredArgsConstructor
public class ApiKeyRevocationPublisher {

  public static final String CHANNEL = "passkey:api-key:revoked";

  private final StringRedisTemplate redis;

  public void publish(UUID apiKeyId) {
    redis.convertAndSend(CHANNEL, apiKeyId.toString());
  }
}
