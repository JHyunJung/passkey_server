package com.crosscert.passkey.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Reference RP server demonstrating {@code passkey-rp-spring-boot-starter}.
 *
 * <p>The starter auto-configures everything passkey-related: the five ceremony endpoints under
 * {@code /passkey/**}, JWT verification, the security filter chain, exception handling and metrics.
 * This application only adds what the SDK intentionally does not cover — a user store, a signup
 * endpoint, credential-management wrappers, and a static demo page.
 */
@SpringBootApplication
public class PasskeyRpDemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(PasskeyRpDemoApplication.class, args);
  }
}
