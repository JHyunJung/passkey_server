package com.crosscert.passkey.integration.tenant.isolation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Pinned to the same physical connection: opens a connection on the runtime DataSource, sets {@code
 * app.current_tenant} to tenant A, and then queries for tenant B's row id. RLS must yield zero rows
 * — proving isolation holds at the DB layer even when the application bypasses the domain
 * repositories.
 */
class RawSqlBypassTest extends IntegrationTestBase {

  @Autowired TenantSeed seed;
  @Autowired DataSource runtimeDataSource;

  @Test
  void native_query_targeting_other_tenant_returns_zero() throws Exception {
    UUID tenantA = seed.createTenant("raw-a-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("raw-b-" + UUID.randomUUID());
    UUID bobId = seed.createUser(tenantB, "bob");

    try (Connection conn = runtimeDataSource.getConnection()) {
      conn.setAutoCommit(false);
      try (PreparedStatement set =
          conn.prepareStatement("SELECT set_config('app.current_tenant', ?, true)")) {
        set.setString(1, tenantA.toString());
        set.execute();
      }

      try (PreparedStatement ps =
          conn.prepareStatement("SELECT count(*) FROM passkey.tenant_user WHERE id = ?")) {
        ps.setObject(1, bobId);
        try (ResultSet rs = ps.executeQuery()) {
          rs.next();
          assertThat(rs.getInt(1)).isZero();
        }
      }

      conn.rollback();
    }
  }
}
