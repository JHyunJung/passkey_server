package com.crosscert.passkey.ratelimit;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "passkey.rate-limit")
public record RateLimitProperties(
    boolean enabled,
    int registrationPerMinute,
    int authenticationPerMinute,
    int defaultPerMinute,
    int adminLoginPerMinute,
    int credentialAuthVerifyPerMinute) {

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
    if (adminLoginPerMinute <= 0) {
      adminLoginPerMinute = 5;
    }
    if (credentialAuthVerifyPerMinute <= 0) {
      credentialAuthVerifyPerMinute = 10;
    }
  }
}
