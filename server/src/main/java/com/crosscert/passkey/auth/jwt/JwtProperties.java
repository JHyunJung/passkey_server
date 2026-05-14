package com.crosscert.passkey.auth.jwt;

import java.nio.charset.StandardCharsets;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "passkey.jwt")
public record JwtProperties(
    String issuer, String secret, long accessTtlSeconds, long refreshTtlSeconds) {

  public JwtProperties {
    if (secret == null || secret.isBlank()) {
      throw new IllegalStateException("passkey.jwt.secret must be set");
    }
    if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalStateException(
          "passkey.jwt.secret must be at least 32 bytes (got "
              + secret.getBytes(StandardCharsets.UTF_8).length
              + ")");
    }
    if (issuer == null || issuer.isBlank()) {
      issuer = "passkey-platform";
    }
    if (accessTtlSeconds <= 0) {
      accessTtlSeconds = 900; // 15 min
    }
    if (refreshTtlSeconds <= 0) {
      refreshTtlSeconds = 2_592_000; // 30 days
    }
  }
}
