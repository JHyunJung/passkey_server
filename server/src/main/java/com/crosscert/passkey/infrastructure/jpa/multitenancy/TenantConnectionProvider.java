package com.crosscert.passkey.infrastructure.jpa.multitenancy;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.engine.jdbc.connections.spi.MultiTenantConnectionProvider;
import org.springframework.stereotype.Component;

/**
 * Wires Oracle VPD by invoking {@code passkey_ctx_pkg.set_tenant(?)} on the connection Hibernate
 * borrows for each transaction. The setter package writes the value into the {@code PASSKEY_CTX}
 * application context; the VPD predicate function reads it via {@code
 * SYS_CONTEXT('PASSKEY_CTX','TENANT_ID')} and appends a {@code tenant_id = HEXTORAW(...)} filter to
 * every statement.
 *
 * <p>Lifecycle differences from the PostgreSQL counterpart:
 *
 * <ul>
 *   <li>Postgres used {@code SET LOCAL}, scoped to the transaction. Oracle's per-session
 *       application context survives until the session ends — so when HikariCP returns the
 *       connection to the pool we MUST clear it explicitly in {@link #releaseConnection(String,
 *       Connection)}; otherwise a later borrower would inherit the previous tenant.
 *   <li>A {@code null} or empty tenant identifier is bound as NULL, which the package translates
 *       into {@code CLEAR_CONTEXT} → the predicate returns {@code "1 = 0"} → zero rows
 *       (fail-closed).
 * </ul>
 *
 * <p>The package is the only writer to the secure context — clients cannot bypass with a direct
 * {@code DBMS_SESSION.SET_CONTEXT} call because {@code CREATE CONTEXT … USING passkey_ctx_pkg}
 * locks down the namespace.
 */
@Slf4j
@Component
public class TenantConnectionProvider implements MultiTenantConnectionProvider<String> {

  private static final String SET_TENANT_SQL = "{ call passkey_ctx_pkg.set_tenant(?) }";
  private static final String CLEAR_TENANT_SQL = "{ call passkey_ctx_pkg.clear_tenant() }";

  private final DataSource dataSource;

  public TenantConnectionProvider(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public Connection getAnyConnection() throws SQLException {
    return dataSource.getConnection();
  }

  @Override
  public void releaseAnyConnection(Connection connection) throws SQLException {
    connection.close();
  }

  @Override
  public Connection getConnection(String tenantIdentifier) throws SQLException {
    Connection connection = dataSource.getConnection();
    // If set_tenant fails the connection must be returned to the pool — otherwise this
    // security-critical fail-closed path also leaks JDBC connections.
    try {
      String hexId = toHex(tenantIdentifier);
      try (CallableStatement cs = connection.prepareCall(SET_TENANT_SQL)) {
        cs.setString(1, hexId);
        cs.execute();
      }
      if (hexId == null) {
        log.debug("vpd.context.unset tenant=fail-closed");
      } else if (log.isTraceEnabled()) {
        log.trace("vpd.context.set tenantId={}", tenantIdentifier);
      }
      return connection;
    } catch (SQLException | RuntimeException e) {
      try {
        connection.close();
      } catch (SQLException closeEx) {
        e.addSuppressed(closeEx);
      }
      throw e;
    }
  }

  @Override
  public void releaseConnection(String tenantIdentifier, Connection connection)
      throws SQLException {
    // CRITICAL: Oracle application contexts are per-session, not per-transaction. HikariCP pools
    // the underlying physical connection — failure to clear here would leak the previous tenant's
    // context into the next borrower.
    try (CallableStatement cs = connection.prepareCall(CLEAR_TENANT_SQL)) {
      cs.execute();
    } catch (SQLException e) {
      // Best-effort clear. Log and continue closing; HikariCP will validate the connection on
      // next acquisition via the connection-test-query and discard if broken.
      log.warn("vpd.context.clear.failed reason={}", e.getMessage());
    } finally {
      connection.close();
    }
  }

  @Override
  public boolean supportsAggressiveRelease() {
    return false;
  }

  @Override
  public boolean isUnwrappableAs(Class<?> unwrapType) {
    return MultiTenantConnectionProvider.class.equals(unwrapType)
        || TenantConnectionProvider.class.equals(unwrapType);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> T unwrap(Class<T> unwrapType) {
    if (isUnwrappableAs(unwrapType)) {
      return (T) this;
    }
    throw new IllegalArgumentException("Cannot unwrap to " + unwrapType.getName());
  }

  /**
   * Normalises the canonical UUID string into the 32-character lowercase hex form Oracle's {@code
   * HEXTORAW(...)} expects. Returns {@code null} for null/blank input so the setter package issues
   * {@code CLEAR_CONTEXT}.
   */
  private static String toHex(String tenantIdentifier) {
    if (tenantIdentifier == null || tenantIdentifier.isEmpty()) {
      return null;
    }
    return tenantIdentifier.replace("-", "").toLowerCase(java.util.Locale.ROOT);
  }
}
