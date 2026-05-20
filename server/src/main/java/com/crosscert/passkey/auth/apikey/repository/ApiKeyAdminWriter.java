package com.crosscert.passkey.auth.apikey.repository;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Privilege-elevated writer for the {@code api_key} table.
 *
 * <p>{@code api_key} grants {@code INSERT} only to {@code APP_ADMIN} (the {@code APP_RUNTIME} role
 * used by the JPA layer has just {@code SELECT}/{@code UPDATE}). Key issuance therefore cannot go
 * through the JPA {@code save()} path; it is routed here, onto the {@code adminDataSource}.
 *
 * <p>Revocation is intentionally NOT here — it is a {@code status} {@code UPDATE}, which {@code
 * APP_RUNTIME} is granted, so the existing JPA path handles it.
 *
 * <p>Conditional on {@code passkey.admin.enabled=true}: only deployments that run the admin console
 * issue keys, and only they configure the admin data source.
 */
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class ApiKeyAdminWriter {

  private static final String INSERT_SQL =
      "INSERT INTO api_key "
          + "(id, tenant_id, prefix, secret_hash, name, status, created_at, updated_at) "
          + "VALUES (HEXTORAW(:id), HEXTORAW(:tenantId), :prefix, :secretHash, :name, 'ACTIVE', "
          + ":createdAt, :updatedAt)";

  private final NamedParameterJdbcTemplate adminJdbc;

  public ApiKeyAdminWriter(NamedParameterJdbcTemplate adminJdbcTemplate) {
    this.adminJdbc = adminJdbcTemplate;
  }

  /**
   * Inserts a new API key row under {@code APP_ADMIN}. UUIDs are written via {@code HEXTORAW} since
   * the columns are {@code RAW(16)}. Timestamps are passed explicitly to match the
   * application-driven "now" the JPA {@code BaseEntity} uses elsewhere.
   */
  @Transactional("adminTransactionManager")
  public void insert(
      UUID id,
      UUID tenantId,
      String prefix,
      String secretHash,
      String name,
      OffsetDateTime createdAt) {
    adminJdbc.update(
        INSERT_SQL,
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tenantId", hex(tenantId))
            .addValue("prefix", prefix)
            .addValue("secretHash", secretHash)
            .addValue("name", name)
            .addValue("createdAt", createdAt)
            .addValue("updatedAt", createdAt));
  }

  /** Canonical UUID string → 32-char hex for Oracle {@code HEXTORAW}. */
  private static String hex(UUID id) {
    return id.toString().replace("-", "");
  }
}
