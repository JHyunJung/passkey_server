package com.crosscert.passkey.credential.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.Getter;
import org.springframework.stereotype.Component;

@Getter
@Component
public class CeremonyMetrics {

  private final Counter registrationSuccess;
  private final Counter registrationFailure;
  private final Counter authenticationSuccess;
  private final Counter authenticationFailure;
  private final Counter signatureCounterRegression;

  public CeremonyMetrics(MeterRegistry registry) {
    this.registrationSuccess =
        Counter.builder("passkey.registration").tag("outcome", "success").register(registry);
    this.registrationFailure =
        Counter.builder("passkey.registration").tag("outcome", "failure").register(registry);
    this.authenticationSuccess =
        Counter.builder("passkey.authentication").tag("outcome", "success").register(registry);
    this.authenticationFailure =
        Counter.builder("passkey.authentication").tag("outcome", "failure").register(registry);
    this.signatureCounterRegression =
        Counter.builder("passkey.signature_counter_regression").register(registry);
  }
}
