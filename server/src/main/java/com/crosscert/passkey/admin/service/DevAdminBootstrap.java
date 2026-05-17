package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.admin.domain.AdminUser;
import com.crosscert.passkey.admin.repository.AdminUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

/**
 * Dev-only seed: ensures a PLATFORM_OPERATOR account exists so the admin console can be logged into
 * out-of-the-box in local development. Active only on the {@code local} / {@code dev} profiles —
 * production gets nothing. Idempotent (no-op if the email already exists).
 */
@Configuration
@Profile({"local", "dev"})
public class DevAdminBootstrap {

  private static final Logger log = LoggerFactory.getLogger(DevAdminBootstrap.class);

  @Bean
  ApplicationRunner devAdminSeeder(
      AdminUserRepository repository,
      PasswordEncoder passwordEncoder,
      @Value("${passkey.dev.seed-admin.email:dev@local.test}") String email,
      @Value("${passkey.dev.seed-admin.password:devpassword!}") String password,
      @Value("${passkey.dev.seed-admin.display-name:Dev Operator}") String displayName) {
    return args -> seed(repository, passwordEncoder, email, password, displayName);
  }

  @Transactional
  void seed(
      AdminUserRepository repository,
      PasswordEncoder passwordEncoder,
      String email,
      String password,
      String displayName) {
    if (repository.findByEmail(email).isPresent()) {
      log.info("dev admin '{}' already exists — skip seeding", email);
      return;
    }
    AdminUser seeded =
        AdminUser.createPlatformOperator(email, passwordEncoder.encode(password), displayName);
    repository.save(seeded);
    log.warn(
        "dev admin seeded: email='{}' password='{}' (NEVER log this in prod — profile=local/dev only)",
        email,
        password);
  }
}
