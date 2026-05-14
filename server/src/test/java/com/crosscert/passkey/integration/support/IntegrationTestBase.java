package com.crosscert.passkey.integration.support;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Integration test base. Connects to the docker-compose Postgres at localhost:5432.
 *
 * <p>Testcontainers was attempted first but the docker-java client could not negotiate the Docker
 * Desktop socket on this macOS host (empty {@code /info} responses). The docker-compose route is
 * functionally equivalent for M1 isolation testing — the same V1__baseline.sql creates the {@code
 * app_runtime} and {@code app_admin} roles, and the runtime DataSource uses {@code app_runtime}
 * (NOBYPASSRLS), so RLS is exercised the same way.
 *
 * <p>Prerequisite: {@code docker compose up -d} from the {@code server/} directory.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
@ActiveProfiles("test")
@Import(TestSupportConfig.class)
public abstract class IntegrationTestBase {

  private static final String JDBC_URL = "jdbc:postgresql://localhost:5432/passkey";

  @DynamicPropertySource
  static void registerProperties(DynamicPropertyRegistry registry) {
    // Runtime DataSource uses app_runtime (NOBYPASSRLS) — exercises RLS.
    registry.add("spring.datasource.url", () -> JDBC_URL);
    registry.add("spring.datasource.username", () -> "app_runtime");
    registry.add("spring.datasource.password", () -> "change_me_local");

    // Flyway uses app_migrator (owner) and creates app_runtime / app_admin via V1.
    registry.add("spring.flyway.url", () -> JDBC_URL);
    registry.add("spring.flyway.user", () -> "app_migrator");
    registry.add("spring.flyway.password", () -> "change_me_local");
    registry.add("spring.flyway.placeholders.app_runtime_password", () -> "change_me_local");
    registry.add("spring.flyway.placeholders.app_admin_password", () -> "change_me_admin");
    // Flyway clean before each integration run so isolation between test classes is stable.
    registry.add("spring.flyway.clean-disabled", () -> "false");

    registry.add("passkey.admin.enabled", () -> "false");
  }
}
