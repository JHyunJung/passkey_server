package com.crosscert.passkey.integration.support;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Integration test base. Connects to the docker-compose Oracle Free PDB at localhost:1521.
 *
 * <p>Testcontainers was attempted first but the docker-java client could not negotiate the Docker
 * Desktop socket on this macOS host (empty {@code /info} responses). The docker-compose route is
 * functionally equivalent for tenant-isolation testing — the same V1__oracle_baseline.sql creates
 * the {@code APP_RUNTIME} and {@code APP_ADMIN} users (the latter holding {@code EXEMPT ACCESS
 * POLICY}), and the runtime DataSource uses {@code APP_RUNTIME}, so VPD is exercised the same way.
 *
 * <p>Prerequisite: {@code docker compose up -d} from the {@code server/} directory (Oracle Free
 * image with {@code APP_MIGRATOR} as the SYSDBA-bootstrapped owner of the PASSKEY objects).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
@ActiveProfiles("test")
@Import(TestSupportConfig.class)
public abstract class IntegrationTestBase {

  private static final String JDBC_URL = "jdbc:oracle:thin:@//localhost:1521/FREEPDB1";

  @DynamicPropertySource
  static void registerProperties(DynamicPropertyRegistry registry) {
    // Runtime DataSource uses APP_RUNTIME (no EXEMPT ACCESS POLICY) — exercises VPD predicates.
    // V1__oracle_baseline.sql creates APP_RUNTIME with the password bound from the Flyway
    // placeholder below, so the value here must match exactly.
    registry.add("spring.datasource.url", () -> JDBC_URL);
    registry.add("spring.datasource.username", () -> "APP_RUNTIME");
    registry.add("spring.datasource.password", () -> "ChangeMeRuntime#1");

    // Flyway uses APP_MIGRATOR (object owner) — the docker-compose image bootstraps that user
    // with the password below. The baseline migration then creates APP_RUNTIME and APP_ADMIN
    // users plus grants and the secure application context.
    registry.add("spring.flyway.url", () -> JDBC_URL);
    registry.add("spring.flyway.user", () -> "APP_MIGRATOR");
    registry.add("spring.flyway.password", () -> "change_me_migrator");
    registry.add("spring.flyway.placeholders.app_runtime_password", () -> "ChangeMeRuntime#1");
    registry.add("spring.flyway.placeholders.app_admin_password", () -> "ChangeMeAdmin#1");
    // Flyway clean before each integration run so isolation between test classes is stable.
    // Oracle Flyway clean drops the Flyway-tracked objects only — public synonyms and the
    // application context survive across reruns unless dropped explicitly in the docker init
    // script.
    registry.add("spring.flyway.clean-disabled", () -> "false");

    registry.add("passkey.admin.enabled", () -> "false");
  }
}
