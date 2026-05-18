package com.crosscert.passkey.integration.tenant.isolation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Drift detection: asserts that every expected tenant-scoped table has a VPD policy attached. Any
 * new tenant-scoped table must be added to {@code EXPECTED_TABLES} — or this test fails and the
 * developer is forced to update {@code R__vpd_policies.sql}.
 *
 * <p>Catalog source: {@code USER_POLICIES} (the table owner's view of all VPD policies attached to
 * objects it owns). The {@code APP_MIGRATOR} user owns the tables, so we run the query as
 * APP_MIGRATOR-equivalent via the runtime DataSource — Oracle restricts USER_POLICIES to the
 * current user's objects, so we use ALL_POLICIES filtered by OBJECT_OWNER instead. APP_RUNTIME has
 * SELECT on ALL_POLICIES via the standard catalog grants.
 */
class RlsPolicyCatalogTest extends IntegrationTestBase {

  /** Update this list when introducing a new tenant-scoped table. */
  private static final List<String> EXPECTED_TABLES =
      List.of(
          "TENANT_USER",
          "TENANT_WEBAUTHN_CONFIG",
          "CREDENTIAL",
          "TENANT_ATTESTATION_POLICY",
          "AUDIT_LOG",
          "REFRESH_TOKEN");

  @Autowired DataSource runtimeDataSource;

  @Test
  void all_tenant_scoped_tables_have_a_vpd_policy() {
    JdbcTemplate jdbc = new JdbcTemplate(runtimeDataSource);

    for (String table : EXPECTED_TABLES) {
      Integer policyCount =
          jdbc.queryForObject(
              "SELECT COUNT(*) FROM ALL_POLICIES "
                  + "WHERE OBJECT_OWNER = 'APP_MIGRATOR' "
                  + "  AND OBJECT_NAME = ? "
                  + "  AND PF_OWNER = 'APP_MIGRATOR' "
                  + "  AND PACKAGE IS NULL "
                  + "  AND ENABLE = 'YES'",
              Integer.class,
              table);

      assertThat(policyCount)
          .as("at least one ENABLED VPD policy on %s", table)
          .isNotNull()
          .isGreaterThanOrEqualTo(1);
    }
  }
}
