package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.domain.AuditCategory;
import com.crosscert.passkey.audit.domain.AuditEventType;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.distribution.HistogramSnapshot;
import io.micrometer.core.instrument.distribution.ValueAtPercentile;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Cross-tenant Activity 페이지의 데이터 집계 서비스.
 *
 * <p>모든 SQL은 {@code APP_ADMIN} (EXEMPT ACCESS POLICY)로 동작하는 {@code adminJdbcTemplate} 위에서 실행되므로
 * VPD가 tenant predicate를 붙이지 않는다 — cross-tenant 합산이 가능. controller는 {@link
 * com.crosscert.passkey.admin.security.AdminAuthz#requirePlatformOperator()}로 권한을 게이트하고 이 서비스는 권한
 * 검사를 다시 하지 않는다 (이중화 금지).
 *
 * <p>HTTP latency는 Spring Boot Actuator의 {@code http.server.requests} Micrometer 타이머에서 직접 snapshot을
 * 읽는다 — Prometheus endpoint 노출 불필요.
 */
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class PlatformActivityService {

  /** Tenant top-N에 들어가는 한 줄. */
  public record TopTenantRow(
      UUID tenantId, String slug, String name, long eventCount24h, long activeCredentials) {}

  /** Latency snapshot — null이면 메트릭 워밍업 전. */
  public record LatencySnapshot(Double avgMs, Double p95Ms, Double p99Ms) {}

  /** activity-summary 응답 형태. */
  public record ActivitySummary(
      String window,
      long activity24h,
      long adminMutations24h,
      long securityEvents24h,
      LatencySnapshot latency,
      List<TopTenantRow> topTenants) {}

  private static final String COUNT_TOTAL_SINCE =
      "SELECT count(*) FROM audit_log WHERE created_at >= :since";

  private static final String COUNT_SINCE_BY_TYPES =
      "SELECT count(*) FROM audit_log "
          + "WHERE event_type IN (:eventTypes) AND created_at >= :since";

  private static final String TOP_TENANTS_BY_EVENT_COUNT =
      "SELECT t.id AS tenant_id, t.slug, t.name, "
          + "  (SELECT count(*) FROM audit_log a "
          + "     WHERE a.tenant_id = t.id AND a.created_at >= :since) AS event_count, "
          + "  (SELECT count(*) FROM credential c "
          + "     WHERE c.tenant_id = t.id AND c.status = 'ACTIVE') AS active_credentials "
          + "FROM tenant t "
          + "ORDER BY event_count DESC "
          + "FETCH FIRST :n ROWS ONLY";

  private final NamedParameterJdbcTemplate adminJdbc;
  private final MeterRegistry meterRegistry;

  public PlatformActivityService(
      NamedParameterJdbcTemplate adminJdbcTemplate, MeterRegistry meterRegistry) {
    this.adminJdbc = adminJdbcTemplate;
    this.meterRegistry = meterRegistry;
  }

  @Transactional(value = "adminTransactionManager", readOnly = true)
  public ActivitySummary summary(String window) {
    OffsetDateTime since = OffsetDateTime.now(ZoneOffset.UTC).minusHours(24);
    long total = countSince(null, since);
    long adminMutations = countSinceForCategory(AuditCategory.ADMIN_ACTION, since);
    long securityEvents = countSinceForCategory(AuditCategory.SECURITY_FAIL, since);
    LatencySnapshot latency = httpLatencySnapshot();
    List<TopTenantRow> top = topTenants(since, 5);
    return new ActivitySummary("24h", total, adminMutations, securityEvents, latency, top);
  }

  // ---- private helpers ----

  private long countSince(AuditCategory category, OffsetDateTime since) {
    if (category == null) {
      return adminJdbc.queryForObject(
          COUNT_TOTAL_SINCE, new MapSqlParameterSource().addValue("since", since), Long.class);
    }
    return countSinceForCategory(category, since);
  }

  private long countSinceForCategory(AuditCategory category, OffsetDateTime since) {
    Set<String> typeNames = new HashSet<>();
    for (AuditEventType t : AuditEventType.values()) {
      if (t.category() == category) {
        typeNames.add(t.name());
      }
    }
    if (typeNames.isEmpty()) {
      return 0L;
    }
    return adminJdbc.queryForObject(
        COUNT_SINCE_BY_TYPES,
        new MapSqlParameterSource().addValue("eventTypes", typeNames).addValue("since", since),
        Long.class);
  }

  private LatencySnapshot httpLatencySnapshot() {
    var timers = meterRegistry.find("http.server.requests").timers();
    if (timers.isEmpty()) {
      return new LatencySnapshot(null, null, null);
    }
    long totalCount = 0;
    double totalTimeMs = 0;
    Double p95 = null;
    Double p99 = null;
    for (Timer t : timers) {
      totalCount += t.count();
      totalTimeMs += t.totalTime(java.util.concurrent.TimeUnit.MILLISECONDS);
      HistogramSnapshot snap = t.takeSnapshot();
      for (ValueAtPercentile v : snap.percentileValues()) {
        double ms = v.value(java.util.concurrent.TimeUnit.MILLISECONDS);
        if (v.percentile() == 0.95) p95 = max(p95, ms);
        if (v.percentile() == 0.99) p99 = max(p99, ms);
      }
    }
    Double avg = totalCount == 0 ? null : totalTimeMs / totalCount;
    return new LatencySnapshot(avg, p95, p99);
  }

  private static Double max(Double a, double b) {
    return a == null ? b : Math.max(a, b);
  }

  private List<TopTenantRow> topTenants(OffsetDateTime since, int limit) {
    return adminJdbc.query(
        TOP_TENANTS_BY_EVENT_COUNT,
        new MapSqlParameterSource().addValue("since", since).addValue("n", limit),
        (rs, rowNum) ->
            new TopTenantRow(
                bytesToUuid(rs.getBytes("tenant_id")),
                rs.getString("slug"),
                rs.getString("name"),
                rs.getLong("event_count"),
                rs.getLong("active_credentials")));
  }

  private static UUID bytesToUuid(byte[] bytes) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes);
    return new UUID(bb.getLong(), bb.getLong());
  }

  // feed는 task 5에서 추가
}
