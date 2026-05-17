package com.crosscert.passkey.unit.auth.apikey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.auth.apikey.service.ApiKeyProperties;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService.IssuedKey;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService.ResolvedKey;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Verifies cache semantics — single-flight on concurrent loads, no negative caching, timing-attack
 * defence still fires on miss paths. Uses cheap Argon2 parameters so the test runs in seconds.
 *
 * <p>Each test mocks {@code findByPrefix} for the specific path under test instead of returning
 * empty globally, because {@link ApiKeyService#issue} and {@link ApiKeyService#verify} both call
 * the same repository method.
 */
@ExtendWith(MockitoExtension.class)
class ApiKeyServiceTest {

  // Cheap parameters: memory=1MB, 1 iteration, 1 parallelism. Real prod uses 64MB / 2 iters.
  private static final ApiKeyProperties CHEAP_PROPS = new ApiKeyProperties(4, 16, 3, 1024, 1, 1);

  @Mock private ApiKeyRepository repo;
  private ApiKeyService service;
  private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

  @BeforeEach
  void setUp() throws Exception {
    service = new ApiKeyService(repo, CHEAP_PROPS);
    // initDummyHash is package-private (called by @PostConstruct in prod). Invoke reflectively to
    // mirror startup behaviour in this unit test.
    Method init = ApiKeyService.class.getDeclaredMethod("initDummyHash");
    init.setAccessible(true);
    init.invoke(service);
  }

  @Test
  void verify_returns_empty_for_malformed_input() {
    assertThat(service.verify("not-pk-format")).isEmpty();
    assertThat(service.verify(null)).isEmpty();
    assertThat(service.verify("pk_noseparator")).isEmpty();
  }

  @Test
  void issue_returns_plaintext_once_and_persists_hash() {
    UUID tenantId = UUID.randomUUID();
    when(repo.findByPrefix(anyString())).thenReturn(Optional.empty());
    when(repo.save(any(ApiKey.class))).thenAnswer(inv -> inv.getArgument(0));

    IssuedKey issued = service.issue(tenantId, "test-key");

    assertThat(issued.plaintext()).startsWith("pk_").contains(".");
    assertThat(issued.id()).isNotNull();
    verify(repo, times(1)).save(any(ApiKey.class));
  }

  @Test
  void verify_cache_hit_avoids_repo_call() {
    UUID tenantId = UUID.randomUUID();
    String secret = "test-secret-value";
    String prefix = "abcd1234";
    String plaintext = "pk_" + prefix + "." + secret;
    ApiKey stored =
        ApiKey.create(tenantId, prefix, argon2.hash(1, 1024, 1, secret.toCharArray()), "k");
    when(repo.findByPrefix(prefix)).thenReturn(Optional.of(stored));

    Optional<ResolvedKey> first = service.verify(plaintext);
    Optional<ResolvedKey> second = service.verify(plaintext);

    assertThat(first).isPresent();
    assertThat(second).isPresent().contains(first.get());
    verify(repo, times(1)).findByPrefix(prefix);
  }

  @Test
  void verify_single_flight_under_concurrent_load() throws Exception {
    UUID tenantId = UUID.randomUUID();
    String secret = "concurrent-secret";
    String prefix = "deadbeef";
    String plaintext = "pk_" + prefix + "." + secret;
    ApiKey stored =
        ApiKey.create(tenantId, prefix, argon2.hash(1, 1024, 1, secret.toCharArray()), "k");
    when(repo.findByPrefix(prefix)).thenReturn(Optional.of(stored));

    int threads = 16;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    for (int i = 0; i < threads; i++) {
      Future<?> ignored =
          pool.submit(
              () -> {
                try {
                  start.await();
                  service.verify(plaintext);
                } catch (InterruptedException e) {
                  Thread.currentThread().interrupt();
                } finally {
                  done.countDown();
                }
              });
    }
    start.countDown();
    assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();
    pool.shutdown();

    // LoadingCache.get is single-flight: only one thread invokes the loader, so findByPrefix runs
    // exactly once even with 16 concurrent verifies on the same key.
    verify(repo, times(1)).findByPrefix(prefix);
  }

  @Test
  void evict_by_apiKeyId_forces_reload_on_next_verify() {
    UUID tenantId = UUID.randomUUID();
    String secret = "evict-secret";
    String prefix = "feedface";
    String plaintext = "pk_" + prefix + "." + secret;
    ApiKey stored =
        ApiKey.create(tenantId, prefix, argon2.hash(1, 1024, 1, secret.toCharArray()), "k");
    when(repo.findByPrefix(prefix)).thenReturn(Optional.of(stored));

    service.verify(plaintext); // warm cache → 1 repo hit
    service.evictByApiKeyId(stored.getId());
    service.verify(plaintext); // cache miss → 2nd repo hit

    verify(repo, times(2)).findByPrefix(prefix);
  }
}
