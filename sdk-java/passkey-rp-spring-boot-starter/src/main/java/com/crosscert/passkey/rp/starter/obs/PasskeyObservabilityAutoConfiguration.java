package com.crosscert.passkey.rp.starter.obs;

import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
@ConditionalOnProperty(
    name = "passkey.rp.observability.metrics-enabled",
    havingValue = "true",
    matchIfMissing = true)
public class PasskeyObservabilityAutoConfiguration {

  @Bean
  public MeterBinder passkeyMeterBinder() {
    return new PasskeyMeterBinder();
  }
}
