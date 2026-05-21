package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.auth.apikey.domain.ApiKeyStatus;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Computes platform-wide aggregate stats across <em>all</em> tenants.
 *
 * <p>Oracle VPD locks every JPA query to a single tenant once {@code TenantContextHolder} is set,
 * so cross-tenant aggregation is impossible through the runtime data source. This service runs on
 * the {@code adminDataSource} ({@code APP_ADMIN}, which holds {@code EXEMPT ACCESS POLICY} and
 * therefore bypasses VPD) with native counting SQL — mirroring {@code ApiKeyAdminWriter}.
 *
 * <p>Conditional on {@code passkey.admin.enabled=true}: only admin-console deployments configure
 * the admin data source / transaction manager this service depends on.
 */
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class AdminPlatformStatsService {

  /** Platform-wide aggregate counters spanning every tenant. */
  public record PlatformStats(long activeCredentials, long activeApiKeys, long ceremonies24h) {}

  private static final String COUNT_ACTIVE_CREDENTIALS =
      "SELECT count(*) FROM credential WHERE status = :status";

  private static final String COUNT_ACTIVE_API_KEYS =
      "SELECT count(*) FROM api_key WHERE status = :status";

  private static final String COUNT_CEREMONIES_24H =
      "SELECT count(*) FROM audit_log "
          + "WHERE event_type IN (:eventTypes) AND created_at >= :fromTs";

  private final NamedParameterJdbcTemplate adminJdbc;

  public AdminPlatformStatsService(NamedParameterJdbcTemplate adminJdbcTemplate) {
    this.adminJdbc = adminJdbcTemplate;
  }

  /**
   * Aggregates active credentials, active API keys, and the count of registration/authentication
   * ceremony starts in the trailing 24h — across all tenants. Enum names are always bound as named
   * parameters, never concatenated into the SQL.
   */
  @Transactional(value = "adminTransactionManager", readOnly = true)
  public PlatformStats compute() {
    long activeCredentials =
        count(
            COUNT_ACTIVE_CREDENTIALS,
            new MapSqlParameterSource().addValue("status", CredentialStatus.ACTIVE.name()));

    long activeApiKeys =
        count(
            COUNT_ACTIVE_API_KEYS,
            new MapSqlParameterSource().addValue("status", ApiKeyStatus.ACTIVE.name()));

    List<String> ceremonyEventTypes =
        List.of(
            AuditEventType.REGISTRATION_OPTIONS_REQUESTED.name(),
            AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED.name());
    long ceremonies24h =
        count(
            COUNT_CEREMONIES_24H,
            new MapSqlParameterSource()
                .addValue("eventTypes", ceremonyEventTypes)
                .addValue("fromTs", OffsetDateTime.now(ZoneOffset.UTC).minusHours(24)));

    return new PlatformStats(activeCredentials, activeApiKeys, ceremonies24h);
  }

  private long count(String sql, MapSqlParameterSource params) {
    Long result = adminJdbc.queryForObject(sql, params, Long.class);
    return result == null ? 0L : result;
  }
}
