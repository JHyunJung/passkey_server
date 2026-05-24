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

  /** activity-feed의 한 항목. */
  public record FeedItem(
      UUID id,
      OffsetDateTime createdAt,
      AuditEventType eventType,
      AuditCategory category,
      UUID tenantId,
      String tenantName,
      String actorType,
      String actorIdShort,
      String subjectType,
      String subjectIdShort) {}

  /** activity-feed cursor 페이지. */
  public record FeedPage(List<FeedItem> items, String nextCursor) {}

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
    // TODO(window): currently only 24h is supported; parameter retained for future widening.
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
      return count(COUNT_TOTAL_SINCE, new MapSqlParameterSource().addValue("since", since));
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
    return count(
        COUNT_SINCE_BY_TYPES,
        new MapSqlParameterSource().addValue("eventTypes", typeNames).addValue("since", since));
  }

  private long count(String sql, MapSqlParameterSource params) {
    Long result = adminJdbc.queryForObject(sql, params, Long.class);
    return result == null ? 0L : result;
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

  private static final int FEED_PAGE_SIZE = 30;

  /**
   * Cross-tenant audit feed. Cursor 기반 페이지네이션으로 새 이벤트가 유입돼도 페이지 경계가 흔들리지 않는다. cursor는 마지막으로 반환된 행의
   * ({@code createdAt}, {@code id}) — opaque base64 인코딩.
   *
   * <p>{@code category} ∈ {"all", "ceremony", "admin-action", "security-fail"}. {@code tenantIds}가
   * 비어있으면 모든 tenant. {@code tenantIds.size()}는 Oracle IN-list 제약상 최대 1000.
   */
  @Transactional(value = "adminTransactionManager", readOnly = true)
  public FeedPage feed(String cursor, String category, List<UUID> tenantIds) {
    if (tenantIds != null && tenantIds.size() > 1000) {
      throw new IllegalArgumentException("tenantIds size must be <= 1000 (Oracle IN-list limit)");
    }
    StringBuilder sql =
        new StringBuilder(
            "SELECT a.id, a.created_at, a.event_type, a.tenant_id, t.name AS tenant_name, "
                + "  a.actor_type, a.actor_id, a.subject_type, a.subject_id "
                + "FROM audit_log a JOIN tenant t ON t.id = a.tenant_id "
                + "WHERE 1=1 ");
    MapSqlParameterSource params = new MapSqlParameterSource();

    // category filter
    Set<String> typeFilter = categoryToTypeNames(category);
    if (typeFilter != null) {
      sql.append("AND a.event_type IN (:eventTypes) ");
      params.addValue("eventTypes", typeFilter);
    }

    // tenant filter — RAW(16) IN-list expansion via HEXTORAW(:t0), HEXTORAW(:t1), ...
    // Spring's named-param list expansion on RAW(16) is finicky on Oracle, so we expand at
    // SQL composition time. Same idiom as CredentialAdminWriter / RefreshTokenAdminWriter.
    if (tenantIds != null && !tenantIds.isEmpty()) {
      StringBuilder inClause = new StringBuilder();
      for (int i = 0; i < tenantIds.size(); i++) {
        if (i > 0) inClause.append(',');
        inClause.append("HEXTORAW(:t").append(i).append(")");
        params.addValue("t" + i, uuidToHex(tenantIds.get(i)));
      }
      sql.append("AND a.tenant_id IN (").append(inClause).append(") ");
    }

    // cursor — (createdAt, id) tuple, strict-less compared to last returned row
    if (cursor != null && !cursor.isBlank()) {
      Cursor c = decodeCursor(cursor);
      sql.append(
          "AND (a.created_at < :curTs OR (a.created_at = :curTs AND a.id < HEXTORAW(:curId))) ");
      params.addValue("curTs", c.createdAt());
      params.addValue("curId", uuidToHex(c.id()));
    }

    sql.append("ORDER BY a.created_at DESC, a.id DESC FETCH FIRST :limit ROWS ONLY");
    params.addValue("limit", FEED_PAGE_SIZE + 1); // +1 to detect "has next"

    List<FeedItem> raw =
        adminJdbc.query(
            sql.toString(),
            params,
            (rs, rowNum) -> {
              AuditEventType type = AuditEventType.valueOf(rs.getString("event_type"));
              return new FeedItem(
                  bytesToUuid(rs.getBytes("id")),
                  rs.getObject("created_at", OffsetDateTime.class),
                  type,
                  type.category(),
                  bytesToUuid(rs.getBytes("tenant_id")),
                  rs.getString("tenant_name"),
                  rs.getString("actor_type"),
                  shortId(rs.getString("actor_id")),
                  rs.getString("subject_type"),
                  shortId(rs.getString("subject_id")));
            });

    String nextCursor = null;
    List<FeedItem> page = raw;
    if (raw.size() > FEED_PAGE_SIZE) {
      page = raw.subList(0, FEED_PAGE_SIZE);
      FeedItem last = page.get(page.size() - 1);
      nextCursor = encodeCursor(new Cursor(last.createdAt(), last.id()));
    }
    return new FeedPage(page, nextCursor);
  }

  private static Set<String> categoryToTypeNames(String category) {
    if (category == null || "all".equalsIgnoreCase(category)) return null;
    AuditCategory ac;
    switch (category.toLowerCase(java.util.Locale.ROOT)) {
      case "ceremony":
        ac = AuditCategory.CEREMONY;
        break;
      case "admin-action":
        ac = AuditCategory.ADMIN_ACTION;
        break;
      case "security-fail":
        ac = AuditCategory.SECURITY_FAIL;
        break;
      default:
        return null;
    }
    Set<String> names = new HashSet<>();
    for (AuditEventType t : AuditEventType.values()) {
      if (t.category() == ac) names.add(t.name());
    }
    return names;
  }

  private static String shortId(String id) {
    if (id == null) return null;
    return id.length() <= 12 ? id : id.substring(0, 12);
  }

  // ---- cursor (opaque base64 of "ISO_OFFSET_DATE_TIME|uuid") ----

  private record Cursor(OffsetDateTime createdAt, UUID id) {}

  private static String encodeCursor(Cursor c) {
    String raw = c.createdAt().toString() + "|" + c.id().toString();
    return java.util.Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static Cursor decodeCursor(String cursor) {
    String raw =
        new String(
            java.util.Base64.getUrlDecoder().decode(cursor),
            java.nio.charset.StandardCharsets.UTF_8);
    int sep = raw.indexOf('|');
    if (sep < 0) throw new IllegalArgumentException("invalid cursor");
    return new Cursor(
        OffsetDateTime.parse(raw.substring(0, sep)), UUID.fromString(raw.substring(sep + 1)));
  }

  private static String uuidToHex(UUID u) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(u.getMostSignificantBits());
    bb.putLong(u.getLeastSignificantBits());
    return java.util.HexFormat.of().formatHex(bb.array());
  }
}
