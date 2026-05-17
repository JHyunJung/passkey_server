package com.crosscert.passkey.integration.tenant.isolation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Drift detection: asserts that every expected tenant-scoped table has ENABLE + FORCE row level
 * security and at least one policy. Any new tenant-scoped table must be added to {@code
 * EXPECTED_TABLES} — or this test fails and the developer is forced to update {@code
 * R__rls_policies.sql}.
 */
class RlsPolicyCatalogTest extends IntegrationTestBase {

  /** Update this list when introducing a new tenant-scoped table. */
  private static final List<String> EXPECTED_TABLES =
      List.of(
          "tenant_user",
          "tenant_webauthn_config",
          "credential",
          "tenant_attestation_policy",
          "audit_log",
          "refresh_token");

  @Autowired DataSource runtimeDataSource;

  @Test
  void all_tenant_scoped_tables_have_force_rls_and_at_least_one_policy() {
    JdbcTemplate jdbc = new JdbcTemplate(runtimeDataSource);

    for (String table : EXPECTED_TABLES) {
      Map<String, Object> row =
          jdbc.queryForMap(
              """
              SELECT c.relrowsecurity      AS row_security,
                     c.relforcerowsecurity AS force_row_security,
                     (SELECT count(*) FROM pg_policies p
                       WHERE p.schemaname = 'passkey' AND p.tablename = c.relname) AS policy_count
                FROM pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
               WHERE n.nspname = 'passkey'
                 AND c.relkind IN ('r', 'p')
                 AND c.relname = ?
              """,
              table);

      assertThat(row.get("row_security"))
          .as("RLS must be ENABLED on %s", table)
          .isEqualTo(Boolean.TRUE);
      assertThat(row.get("force_row_security"))
          .as("RLS must be FORCED on %s", table)
          .isEqualTo(Boolean.TRUE);
      assertThat(((Number) row.get("policy_count")).intValue())
          .as("at least one policy on %s", table)
          .isGreaterThanOrEqualTo(1);
    }
  }
}
