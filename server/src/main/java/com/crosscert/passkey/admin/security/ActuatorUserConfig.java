package com.crosscert.passkey.admin.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Standalone {@link InMemoryUserDetailsManager} that backs the {@code actuatorChain} HTTP basic
 * authentication. Kept separate from {@link AdminUserDetailsService} so admin login and actuator
 * scraping cannot share credentials.
 */
@Configuration
public class ActuatorUserConfig {

  @Bean
  public InMemoryUserDetailsManager actuatorUserDetailsService(
      @Value("${passkey.actuator.username:actuator}") String username,
      @Value("${passkey.actuator.password:change-me-actuator}") String password) {
    return new InMemoryUserDetailsManager(
        User.withUsername(username)
            .password("{noop}" + password) // basic-auth only; rotate via env, not at rest
            .roles("ACTUATOR")
            .build());
  }
}
