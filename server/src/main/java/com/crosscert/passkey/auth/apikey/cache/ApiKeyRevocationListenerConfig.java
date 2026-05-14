package com.crosscert.passkey.auth.apikey.cache;

import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.PatternTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

/** Wires a Redis subscriber that evicts the local Caffeine cache when peers publish revocations. */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class ApiKeyRevocationListenerConfig {

  @Bean
  public RedisMessageListenerContainer apiKeyRevocationListenerContainer(
      RedisConnectionFactory connectionFactory, ApiKeyService apiKeyService) {
    RedisMessageListenerContainer container = new RedisMessageListenerContainer();
    container.setConnectionFactory(connectionFactory);
    container.addMessageListener(
        new MessageListenerAdapter(new Handler(apiKeyService)),
        new PatternTopic(ApiKeyRevocationPublisher.CHANNEL));
    return container;
  }

  @RequiredArgsConstructor
  static class Handler {
    private final ApiKeyService apiKeyService;

    @SuppressWarnings("unused") // invoked by MessageListenerAdapter via reflection
    public void handleMessage(byte[] message) {
      String s = new String(message, StandardCharsets.UTF_8);
      try {
        apiKeyService.evictByApiKeyId(UUID.fromString(s));
      } catch (IllegalArgumentException e) {
        log.warn("ignoring malformed revocation payload: {}", s);
      }
    }
  }
}
