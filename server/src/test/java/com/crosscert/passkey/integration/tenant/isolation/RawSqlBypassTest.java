package com.crosscert.passkey.integration.tenant.isolation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Pinned to the same physical connection: opens a connection on the runtime DataSource, sets the
 * Oracle application context {@code PASSKEY_CTX.TENANT_ID} to tenant A via the secure setter
 * package, then queries for tenant B's row id. VPD must yield zero rows — proving isolation holds
 * at the DB layer even when the application bypasses the domain repositories.
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
      try (CallableStatement set = conn.prepareCall("{ call passkey_ctx_pkg.set_tenant(?) }")) {
        set.setString(1, tenantA.toString().replace("-", "").toLowerCase(Locale.ROOT));
        set.execute();
      }

      try (PreparedStatement ps =
          conn.prepareStatement("SELECT count(*) FROM tenant_user WHERE id = ?")) {
        // Oracle stores UUIDs as RAW(16); bind via setBytes so the driver does not try to coerce
        // a java.util.UUID through Object overloads.
        ps.setBytes(1, uuidToBytes(bobId));
        try (ResultSet rs = ps.executeQuery()) {
          rs.next();
          assertThat(rs.getInt(1)).isZero();
        }
      }

      conn.rollback();
    }
  }

  private static byte[] uuidToBytes(UUID u) {
    long msb = u.getMostSignificantBits();
    long lsb = u.getLeastSignificantBits();
    byte[] bytes = new byte[16];
    for (int i = 0; i < 8; i++) {
      bytes[i] = (byte) (msb >>> (8 * (7 - i)));
      bytes[8 + i] = (byte) (lsb >>> (8 * (7 - i)));
    }
    return bytes;
  }
}
