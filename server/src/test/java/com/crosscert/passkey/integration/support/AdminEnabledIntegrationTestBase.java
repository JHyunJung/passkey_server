package com.crosscert.passkey.integration.support;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Integration test base for the admin-console deployment shape ({@code
 * passkey.admin.enabled=true}).
 *
 * <p>Deliberately does <em>not</em> extend {@link IntegrationTestBase}.
 * {@code @DynamicPropertySource} methods are additive across a class hierarchy, so inheriting that
 * base would still apply its {@code passkey.admin.enabled=false} and the admin beans would never be
 * created. This class therefore copies the runtime + Flyway registration verbatim and flips admin
 * on, additionally registering the {@code passkey.admin.datasource.*} properties so {@code
 * DataSourceConfig} / {@code AdminJdbcConfig} can bind the {@code APP_ADMIN} (VPD-exempt) data
 * source, transaction manager, and {@code AdminPlatformStatsService}.
 *
 * <p>Same docker-compose Oracle Free PDB at localhost:1521 as {@link IntegrationTestBase}; Flyway's
 * V1 baseline creates {@code APP_ADMIN} with the password bound from the placeholder below, so the
 * admin data source credentials here must match exactly.
 *
 * <p>Prerequisite: {@code docker compose up -d} from the {@code server/} directory.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
@ActiveProfiles("test")
@Import(TestSupportConfig.class)
public abstract class AdminEnabledIntegrationTestBase {

  private static final String JDBC_URL = "jdbc:oracle:thin:@//localhost:1521/FREEPDB1";
  private static final String APP_ADMIN_PASSWORD = "ChangeMeAdmin#1";

  @DynamicPropertySource
  static void registerProperties(DynamicPropertyRegistry registry) {
    // Runtime DataSource uses APP_RUNTIME (no EXEMPT ACCESS POLICY) — identical to
    // IntegrationTestBase. V1__oracle_baseline.sql creates APP_RUNTIME with the password bound
    // from the Flyway placeholder below, so the value here must match exactly.
    registry.add("spring.datasource.url", () -> JDBC_URL);
    registry.add("spring.datasource.username", () -> "APP_RUNTIME");
    registry.add("spring.datasource.password", () -> "ChangeMeRuntime#1");

    // Flyway uses APP_MIGRATOR (object owner). The baseline migration creates APP_RUNTIME and
    // APP_ADMIN users plus grants and the secure application context.
    registry.add("spring.flyway.url", () -> JDBC_URL);
    registry.add("spring.flyway.user", () -> "APP_MIGRATOR");
    registry.add("spring.flyway.password", () -> "change_me_migrator");
    registry.add("spring.flyway.placeholders.app_runtime_password", () -> "ChangeMeRuntime#1");
    registry.add("spring.flyway.placeholders.app_admin_password", () -> APP_ADMIN_PASSWORD);
    registry.add("spring.flyway.clean-disabled", () -> "false");

    // Admin console deployment shape: enable the APP_ADMIN (VPD-exempt) data source so the
    // adminDataSource / adminJdbcTemplate / adminTransactionManager / AdminPlatformStatsService
    // beans are created. APP_ADMIN holds EXEMPT ACCESS POLICY → cross-tenant aggregation works.
    registry.add("passkey.admin.enabled", () -> "true");
    registry.add("passkey.admin.console-origin", () -> "http://localhost:5173");
    registry.add("passkey.admin.datasource.url", () -> JDBC_URL);
    registry.add("passkey.admin.datasource.username", () -> "APP_ADMIN");
    registry.add("passkey.admin.datasource.password", () -> APP_ADMIN_PASSWORD);
  }
}
