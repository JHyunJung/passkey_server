package com.crosscert.passkey.rp.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Random;
import org.junit.jupiter.api.Test;

class RetryPolicyTest {

  @Test
  void exponential_backoff_grows_per_attempt() {
    RetryPolicy p = new RetryPolicy(3, Duration.ofMillis(100));
    Random fixed = new Random(0);
    Duration a0 = p.backoffFor(0, fixed);
    Duration a1 = p.backoffFor(1, fixed);
    Duration a2 = p.backoffFor(2, fixed);
    assertThat(a1.toMillis()).isGreaterThan(a0.toMillis());
    assertThat(a2.toMillis()).isGreaterThan(a1.toMillis());
    // Sanity bounds: base * 3^attempt ± 20% jitter
    assertThat(a0.toMillis()).isBetween(80L, 120L);
    assertThat(a1.toMillis()).isBetween(240L, 360L);
    assertThat(a2.toMillis()).isBetween(720L, 1080L);
  }
}
