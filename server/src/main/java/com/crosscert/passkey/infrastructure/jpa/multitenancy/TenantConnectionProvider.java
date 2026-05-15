package com.crosscert.passkey.infrastructure.jpa.multitenancy;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.sql.DataSource;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.engine.jdbc.connections.spi.MultiTenantConnectionProvider;
import org.springframework.stereotype.Component;

/**
 * Wires Postgres RLS by issuing {@code SET LOCAL app.current_tenant = ?} on the connection
 * Hibernate borrows for each transaction. {@code SET LOCAL} expires at COMMIT/ROLLBACK, preventing
 * leakage when HikariCP recycles the connection.
 *
 * <p>A {@code null} tenant identifier binds NULL, which makes {@code
 * current_setting('app.current_tenant')} return an empty string. The {@code
 * passkey.current_tenant_id()} helper then returns NULL, yielding zero rows under RLS
 * (fail-closed).
 */
@Slf4j
@Component
public class TenantConnectionProvider implements MultiTenantConnectionProvider<String> {

  private static final String SET_TENANT_SQL = "SELECT set_config('app.current_tenant', ?, true)";

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
    try (PreparedStatement ps = connection.prepareStatement(SET_TENANT_SQL)) {
      ps.setString(1, tenantIdentifier); // null is OK — fail-closed
      ps.execute();
    }
    if (tenantIdentifier == null || tenantIdentifier.isEmpty()) {
      log.debug("rls.context.unset tenant=fail-closed");
    } else if (log.isTraceEnabled()) {
      log.trace("rls.context.set tenantId={}", tenantIdentifier);
    }
    return connection;
  }

  @Override
  public void releaseConnection(String tenantIdentifier, Connection connection)
      throws SQLException {
    connection.close();
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
}
