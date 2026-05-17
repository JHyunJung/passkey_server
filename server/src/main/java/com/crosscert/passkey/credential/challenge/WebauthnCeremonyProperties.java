package com.crosscert.passkey.credential.challenge;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tunables for WebAuthn ceremony orchestration. Defaults mirror the prior hard-coded values:
 * 32-byte challenge, 5-minute Redis TTL matching typical authenticator UX timeouts.
 */
@ConfigurationProperties(prefix = "passkey.webauthn.ceremony")
public record WebauthnCeremonyProperties(int challengeBytes, Duration challengeTtl) {

  public WebauthnCeremonyProperties {
    if (challengeBytes <= 0) {
      challengeBytes = 32;
    }
    if (challengeTtl == null || challengeTtl.isZero() || challengeTtl.isNegative()) {
      challengeTtl = Duration.ofMinutes(5);
    }
  }
}
