package com.crosscert.passkey.credential.webauthn;

import com.webauthn4j.WebAuthnManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebAuthnConfig {

  /**
   * Non-strict manager because v1 does not perform attestation trust validation against MDS.
   * Attestation policy still rejects denied AAGUIDs; trust chain validation is deferred to v1.1.
   */
  @Bean
  public WebAuthnManager webAuthnManager() {
    return WebAuthnManager.createNonStrictWebAuthnManager();
  }
}
