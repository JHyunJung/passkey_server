package com.crosscert.passkey.auth.apikey.service;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tunables for API key issuance and verification.
 *
 * <p>{@code argon2*} parameters only affect newly issued keys — previously hashed secrets carry
 * their own parameter metadata embedded in the encoded hash, so verify-time behaviour is unchanged
 * after a tuning roll-out.
 */
@ConfigurationProperties(prefix = "passkey.api-key")
public record ApiKeyProperties(
    int prefixBytes,
    int secretBytes,
    int maxPrefixAttempts,
    int argon2MemoryKb,
    int argon2Iterations,
    int argon2Parallelism) {

  public ApiKeyProperties {
    if (prefixBytes <= 0) {
      prefixBytes = 6;
    }
    if (secretBytes <= 0) {
      secretBytes = 32;
    }
    if (maxPrefixAttempts <= 0) {
      maxPrefixAttempts = 3;
    }
    if (argon2MemoryKb <= 0) {
      argon2MemoryKb = 65_536;
    }
    if (argon2Iterations <= 0) {
      argon2Iterations = 2;
    }
    if (argon2Parallelism <= 0) {
      argon2Parallelism = 1;
    }
  }
}
