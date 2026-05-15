package com.crosscert.passkey.auth.apikey.service;

import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.annotation.PostConstruct;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ApiKeyService {

  private static final SecureRandom RNG = new SecureRandom();
  private static final String KEY_VERSION = "pk";
  private static final int PREFIX_BYTES = 6;
  private static final int SECRET_BYTES = 32;
  private static final int MAX_PREFIX_ATTEMPTS = 3;

  private final ApiKeyRepository repo;
  private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

  /**
   * Per-JVM cache of verified API keys. Cuts Argon2 verify (~150-300 ms) down to a hashmap lookup
   * after the first request. Cross-instance invalidation is handled by {@code
   * ApiKeyRevocationListenerConfig} subscribing to the Redis pub/sub channel.
   */
  private final Cache<String, ResolvedKey> verifiedCache =
      Caffeine.newBuilder().expireAfterWrite(Duration.ofMinutes(5)).maximumSize(10_000).build();

  /**
   * Dummy hash used to keep {@link #verify} latency uniform across cache miss / unknown prefix /
   * malformed input. Built once at startup against a throw-away secret.
   */
  private String dummyHash;

  @PostConstruct
  void initDummyHash() {
    this.dummyHash = argon2.hash(2, 65_536, 1, "init-dummy-secret".toCharArray());
  }

  public record IssuedKey(UUID id, String plaintext, String prefix) {}

  public record ResolvedKey(UUID tenantId, UUID apiKeyId) {}

  @Transactional
  public IssuedKey issue(UUID tenantId, String name) {
    for (int attempt = 0; attempt < MAX_PREFIX_ATTEMPTS; attempt++) {
      String prefix = randomBase64Url(PREFIX_BYTES);
      if (repo.findByPrefix(prefix).isPresent()) {
        continue;
      }
      String secret = randomBase64Url(SECRET_BYTES);
      String plaintext = KEY_VERSION + "_" + prefix + "." + secret;
      String secretHash = argon2.hash(2, 65_536, 1, secret.toCharArray());
      ApiKey saved = repo.save(ApiKey.create(tenantId, prefix, secretHash, name));
      log.info(
          "apikey.issued tenantId={} apiKeyId={} prefix={} name={}",
          tenantId,
          saved.getId(),
          prefix,
          name);
      return new IssuedKey(saved.getId(), plaintext, prefix);
    }
    throw new BusinessException(
        ErrorCode.INTERNAL_SERVER_ERROR, "api key prefix collision after retries");
  }

  /** Returns the resolved (tenantId, apiKeyId) or empty if verification fails. */
  @Transactional
  public Optional<ResolvedKey> verify(String presented) {
    ResolvedKey cached = verifiedCache.getIfPresent(presented);
    if (cached != null) {
      return Optional.of(cached);
    }
    Optional<ResolvedKey> result = doVerify(presented);
    result.ifPresent(rk -> verifiedCache.put(presented, rk));
    return result;
  }

  /** Drops cached entries that match the given apiKeyId. Invoked by Redis revocation listener. */
  public void evictByApiKeyId(UUID apiKeyId) {
    verifiedCache.asMap().entrySet().removeIf(e -> e.getValue().apiKeyId().equals(apiKeyId));
  }

  private Optional<ResolvedKey> doVerify(String presented) {
    String secret = "x";
    if (presented == null || !presented.startsWith(KEY_VERSION + "_")) {
      argon2.verify(dummyHash, secret.toCharArray());
      log.warn("apikey.verify.malformed reason=missing_or_bad_version");
      return Optional.empty();
    }
    String body = presented.substring(KEY_VERSION.length() + 1);
    int dot = body.indexOf('.');
    if (dot < 0) {
      argon2.verify(dummyHash, secret.toCharArray());
      log.warn("apikey.verify.malformed reason=no_dot_separator");
      return Optional.empty();
    }
    String prefix = body.substring(0, dot);
    secret = body.substring(dot + 1);

    Optional<ApiKey> found = repo.findByPrefix(prefix);
    if (found.isEmpty()) {
      argon2.verify(dummyHash, secret.toCharArray());
      log.warn("apikey.verify.unknown_prefix prefix={}", prefix);
      return Optional.empty();
    }
    ApiKey k = found.get();
    if (!k.isActive()) {
      argon2.verify(dummyHash, secret.toCharArray());
      log.warn(
          "apikey.verify.revoked prefix={} apiKeyId={} tenantId={}",
          prefix,
          k.getId(),
          k.getTenantId());
      throw new BusinessException(ErrorCode.INVALID_API_KEY);
    }
    if (!argon2.verify(k.getSecretHash(), secret.toCharArray())) {
      log.warn(
          "apikey.verify.secret_mismatch prefix={} apiKeyId={} tenantId={}",
          prefix,
          k.getId(),
          k.getTenantId());
      return Optional.empty();
    }
    k.recordUse();
    log.debug(
        "apikey.verify.success prefix={} apiKeyId={} tenantId={}",
        prefix,
        k.getId(),
        k.getTenantId());
    return Optional.of(new ResolvedKey(k.getTenantId(), k.getId()));
  }

  private static String randomBase64Url(int bytes) {
    byte[] buf = new byte[bytes];
    RNG.nextBytes(buf);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
  }
}
