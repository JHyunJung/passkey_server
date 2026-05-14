package com.crosscert.passkey.ratelimit;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "passkey.rate-limit")
public record RateLimitProperties(
    boolean enabled, int registrationPerMinute, int authenticationPerMinute, int defaultPerMinute) {

  public RateLimitProperties {
    if (registrationPerMinute <= 0) {
      registrationPerMinute = 30;
    }
    if (authenticationPerMinute <= 0) {
      authenticationPerMinute = 60;
    }
    if (defaultPerMinute <= 0) {
      defaultPerMinute = 120;
    }
  }
}
