package com.crosscert.passkey.auth.jwt;

import java.nio.charset.StandardCharsets;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT signing/verification configuration with optional previous-secret support for zero-downtime
 * key rotation.
 *
 * <p>Rotation flow:
 *
 * <ol>
 *   <li>Operator generates a fresh 32-byte secret.
 *   <li>Set the new value as {@code PASSKEY_JWT_SECRET} and the current value as {@code
 *       PASSKEY_JWT_SECRET_PREVIOUS}; restart.
 *   <li>{@link TokenService} signs new tokens with the primary secret but accepts both for
 *       verification — outstanding access/refresh tokens keep working.
 *   <li>After the longest refresh TTL window (30 days by default) all remaining tokens have rotated
 *       onto the primary key; clear {@code PASSKEY_JWT_SECRET_PREVIOUS} on the next deploy.
 * </ol>
 */
@ConfigurationProperties(prefix = "passkey.jwt")
public record JwtProperties(
    String issuer,
    String secret,
    String previousSecret,
    long accessTtlSeconds,
    long refreshTtlSeconds) {

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
    if (previousSecret != null
        && !previousSecret.isBlank()
        && previousSecret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalStateException(
          "passkey.jwt.previous-secret must be at least 32 bytes when set (got "
              + previousSecret.getBytes(StandardCharsets.UTF_8).length
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

  /** True when a previous-secret is configured and rotation is in progress. */
  public boolean hasPreviousSecret() {
    return previousSecret != null && !previousSecret.isBlank();
  }
}
