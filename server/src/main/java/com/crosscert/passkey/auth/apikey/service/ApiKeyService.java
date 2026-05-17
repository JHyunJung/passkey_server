package com.crosscert.passkey.auth.apikey.service;

import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
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

  private final ApiKeyRepository repo;
  private final ApiKeyProperties props;
  private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

  /**
   * Per-JVM cache of verified API keys. Cuts Argon2 verify (~150-300 ms) down to a hashmap lookup
   * after the first request. Cross-instance invalidation is handled by {@code
   * ApiKeyRevocationListenerConfig} subscribing to the Redis pub/sub channel.
   *
   * <p>Wrapped values mean negative results are intentionally NOT cached — every malformed /
   * unknown / wrong-secret request re-runs {@link #doVerify} so the Argon2 timing-uniformity
   * defence (dummy hash on every miss path) keeps working. {@code LoadingCache} guarantees
   * single-flight: when 100 concurrent requests for the same valid key arrive after an eviction,
   * only one Argon2 verify runs and the rest reuse its result.
   */
  private final LoadingCache<String, Optional<ResolvedKey>> verifiedCache =
      Caffeine.newBuilder()
          .expireAfterWrite(Duration.ofMinutes(5))
          .maximumSize(10_000)
          .build(this::loadVerified);

  private Optional<ResolvedKey> loadVerified(String presented) {
    Optional<ResolvedKey> resolved = doVerify(presented);
    if (resolved.isEmpty()) {
      // Defeat negative caching: throw a sentinel so Caffeine drops the entry. Callers map this
      // back to Optional.empty().
      throw new ApiKeyNotResolved();
    }
    return resolved;
  }

  private static final class ApiKeyNotResolved extends RuntimeException {
    ApiKeyNotResolved() {
      super(null, null, false, false);
    }
  }

  /**
   * Dummy hash used to keep {@link #verify} latency uniform across cache miss / unknown prefix /
   * malformed input. Built once at startup against a throw-away secret.
   */
  private String dummyHash;

  @PostConstruct
  void initDummyHash() {
    this.dummyHash =
        argon2.hash(
            props.argon2Iterations(),
            props.argon2MemoryKb(),
            props.argon2Parallelism(),
            "init-dummy-secret".toCharArray());
  }

  /**
   * Startup hook: (a) catch-up sweep evicts any REVOKED entries from the verified cache, (b) JIT
   * warm-up runs a handful of dummy Argon2 verifies so the first real request doesn't pay the
   * tiered-compilation tax on top of the cache miss. We cannot pre-verify real keys because the
   * server stores only their Argon2 hash — plaintext is shown once at issue time and never again.
   * The combination of single-flight {@link LoadingCache} + JIT-warm Argon2 keeps thread starvation
   * bounded during a mass eviction (e.g. JVM restart, large pub/sub revocation wave).
   */
  @org.springframework.context.event.EventListener(
      org.springframework.boot.context.event.ApplicationReadyEvent.class)
  @org.springframework.transaction.annotation.Transactional(readOnly = true)
  public void evictRevokedOnStartup() {
    try {
      int evicted = 0;
      for (ApiKey k : repo.findAll().stream().filter(k -> !k.isActive()).toList()) {
        evictByApiKeyId(k.getId());
        evicted++;
      }
      log.info("apikey.cache.startup.evict.done revoked_keys={}", evicted);
    } catch (RuntimeException ex) {
      // Non-fatal — the per-request status check is the authoritative gate.
      log.warn("apikey.cache.startup.evict.failed reason={}", ex.toString());
    }
    warmUpArgon2Verify();
  }

  /**
   * Drive Argon2.verify() a few times against the dummy hash so the HotSpot tiered compiler
   * promotes it to C2 before serving real traffic. First-cold Argon2.verify can take 2-3× the
   * steady-state cost on a JVM that has never run it.
   */
  private void warmUpArgon2Verify() {
    if (dummyHash == null) {
      return;
    }
    long started = System.nanoTime();
    for (int i = 0; i < 3; i++) {
      argon2.verify(dummyHash, "warmup".toCharArray());
    }
    long elapsedMs = (System.nanoTime() - started) / 1_000_000;
    log.info("apikey.argon2.warmup.done iterations=3 elapsedMs={}", elapsedMs);
  }

  public record IssuedKey(UUID id, String plaintext, String prefix) {}

  public record ResolvedKey(UUID tenantId, UUID apiKeyId) {}

  /**
   * Issues a fresh API key for {@code tenantId}. Returns the plaintext form ({@code
   * pk_<prefix>.<secret>}) once — the server stores only the Argon2id hash of the secret. Retries
   * up to {@code MAX_PREFIX_ATTEMPTS} on prefix collision; throws {@link BusinessException} ({@code
   * INTERNAL_SERVER_ERROR}) if collisions persist.
   */
  @Transactional
  public IssuedKey issue(UUID tenantId, String name) {
    for (int attempt = 0; attempt < props.maxPrefixAttempts(); attempt++) {
      String prefix = randomBase64Url(props.prefixBytes());
      if (repo.findByPrefix(prefix).isPresent()) {
        continue;
      }
      String secret = randomBase64Url(props.secretBytes());
      String plaintext = KEY_VERSION + "_" + prefix + "." + secret;
      String secretHash =
          argon2.hash(
              props.argon2Iterations(),
              props.argon2MemoryKb(),
              props.argon2Parallelism(),
              secret.toCharArray());
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

  /**
   * Resolves the presented API key to a {@link ResolvedKey}, or returns empty if it is malformed,
   * unknown, or its secret does not match. Throws {@link BusinessException} ({@code
   * INVALID_API_KEY}) when the prefix matches a revoked row — the caller treats this as a hard
   * failure rather than a silent miss. Cache hits skip Argon2; misses pay ~150-300 ms but a uniform
   * dummy hash is run on every failure path to keep timing flat across all error cases.
   */
  @Transactional
  public Optional<ResolvedKey> verify(String presented) {
    if (presented == null) {
      return Optional.empty();
    }
    try {
      return verifiedCache.get(presented);
    } catch (ApiKeyNotResolved expected) {
      return Optional.empty();
    }
  }

  /** Drops cached entries that match the given apiKeyId. Invoked by Redis revocation listener. */
  public void evictByApiKeyId(UUID apiKeyId) {
    verifiedCache
        .asMap()
        .entrySet()
        .removeIf(e -> e.getValue().map(rk -> rk.apiKeyId().equals(apiKeyId)).orElse(false));
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
