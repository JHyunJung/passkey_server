package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.audit.service.AuditService.ChainVerification;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.distribution.HistogramSnapshot;
import io.micrometer.core.instrument.distribution.ValueAtPercentile;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Cross-tenant audit hash-chain 무결성 모니터링 데이터 + 즉시 검증 orchestrator.
 *
 * <p>두 가지 DB 경로를 혼합한다. (a) tenant 목록 조회는 {@code adminJdbcTemplate} (APP_ADMIN, VPD exempt)로
 * auto-commit SELECT. (b) 실제 hash chain 재검증은 {@link AuditService#verifyIntegrity}가 VPD-bound이므로
 * tenant별로 {@link TenantContextHolder#set} 후 호출하고 finally에서 {@link TenantContextHolder#clear}.
 *
 * <p>{@link #status()} 는 {@code adminTransactionManager}로 tenant 목록을 읽고, Caffeine 캐시(TTL 60s)에서 최신
 * verify 결과를 반환한다. {@link #verifyAll()} 은 트랜잭션 없이 모든 tenant를 직렬 재검증하고 캐시를 갱신한다.
 */
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class PlatformAuditChainService {

  // ---- public record types ----

  public record TenantChainRow(
      UUID tenantId,
      String slug,
      String name,
      String status, // "INTACT" | "TAMPERED"
      long verifiedRows,
      OffsetDateTime lastVerifiedAt,
      int tamperedRowCount) {}

  public record TamperedTenantSummary(
      UUID tenantId,
      String slug,
      String name,
      int tamperedRowCount,
      OffsetDateTime lastVerifiedAt) {}

  public record ChainStatus(
      int totalTenants,
      int intactTenants,
      List<TamperedTenantSummary> tamperedTenants,
      long totalVerifiedRows,
      String schedulerCron,
      OffsetDateTime schedulerNextRunAt,
      int adminPollingIntervalSec,
      Double lastVerifyAvgMs,
      Double lastVerifyP99Ms,
      List<TenantChainRow> perTenant) {}

  public record VerifyTenantResult(
      UUID tenantId, boolean intact, long verifiedRows, int tamperedRowCount, long durationMs) {}

  public record VerifyAllResult(
      OffsetDateTime startedAt,
      OffsetDateTime completedAt,
      int tenantsChecked,
      int tenantsIntact,
      int tenantsTampered,
      List<VerifyTenantResult> perTenant,
      List<String> errors) {}

  // ---- SQL ----

  private static final String LIST_TENANTS_SQL =
      "SELECT id, slug, name FROM tenant ORDER BY name ASC";

  // ---- dependencies ----

  private final NamedParameterJdbcTemplate adminJdbc;
  private final AuditService auditService;
  private final MeterRegistry meterRegistry;

  /** {@code tenantId → last verify result + timestamp}. TTL 60s. */
  private final Cache<UUID, CachedVerify> verifyCache =
      Caffeine.newBuilder().expireAfterWrite(Duration.ofSeconds(60)).maximumSize(10_000).build();

  // ---- constructor ----

  public PlatformAuditChainService(
      NamedParameterJdbcTemplate adminJdbcTemplate,
      AuditService auditService,
      MeterRegistry meterRegistry) {
    this.adminJdbc = adminJdbcTemplate;
    this.auditService = auditService;
    this.meterRegistry = meterRegistry;
  }

  // ---- public API ----

  /**
   * 모든 ACTIVE tenant의 audit chain 상태를 집계해 반환한다. tenant 목록은 admin 트랜잭션에서 조회하고, 개별 chain 검증 결과는
   * Caffeine 캐시(TTL 60s)에서 반환하거나 miss 시 즉시 재검증한다.
   */
  @Transactional(value = "adminTransactionManager", readOnly = true)
  public ChainStatus status() {
    List<TenantRow> tenants = listTenants();
    List<TenantChainRow> perTenant = new ArrayList<>();
    List<TamperedTenantSummary> tampered = new ArrayList<>();
    int intact = 0;
    long totalVerified = 0;

    for (TenantRow t : tenants) {
      CachedVerify cv = cachedOrVerify(t.id());
      ChainVerification ver = cv.verification();
      int tamperCount = ver.tamperedEntryIds().size();
      String statusStr = ver.intact() ? "INTACT" : "TAMPERED";
      perTenant.add(
          new TenantChainRow(
              t.id(),
              t.slug(),
              t.name(),
              statusStr,
              ver.verifiedRows(),
              cv.verifiedAt(),
              tamperCount));
      if (ver.intact()) {
        intact++;
      } else {
        tampered.add(
            new TamperedTenantSummary(t.id(), t.slug(), t.name(), tamperCount, cv.verifiedAt()));
      }
      totalVerified += ver.verifiedRows();
    }

    LatencyPair lat = verifyLatency();
    return new ChainStatus(
        tenants.size(),
        intact,
        tampered,
        totalVerified,
        "0 30 3 * * *",
        nextDaily0330Utc(OffsetDateTime.now(ZoneOffset.UTC)),
        60,
        lat.avgMs(),
        lat.p99Ms(),
        perTenant);
  }

  /**
   * 모든 tenant의 hash chain을 직렬로 재검증하고 캐시를 갱신한다. 트랜잭션 없이 동작 — 내부 {@link
   * AuditService#verifyIntegrity}가 runtime tx manager로 자체 트랜잭션을 연다.
   */
  public VerifyAllResult verifyAll() {
    OffsetDateTime started = OffsetDateTime.now(ZoneOffset.UTC);
    List<TenantRow> tenants = listTenants();
    List<VerifyTenantResult> results = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    int intact = 0;
    int tampered = 0;

    for (TenantRow t : tenants) {
      long startNanos = System.nanoTime();
      try {
        ChainVerification ver = verifyTenantWithContext(t.id());
        verifyCache.put(t.id(), new CachedVerify(ver, OffsetDateTime.now(ZoneOffset.UTC)));
        long ms = (System.nanoTime() - startNanos) / 1_000_000;
        boolean ok = ver.intact();
        if (ok) intact++;
        else tampered++;
        results.add(
            new VerifyTenantResult(
                t.id(), ok, ver.verifiedRows(), ver.tamperedEntryIds().size(), ms));
      } catch (RuntimeException ex) {
        errors.add("tenant=" + t.id() + " error=" + ex.getMessage());
      }
    }

    OffsetDateTime completed = OffsetDateTime.now(ZoneOffset.UTC);
    return new VerifyAllResult(
        started, completed, tenants.size(), intact, tampered, results, errors);
  }

  // ---- private helpers ----

  private record TenantRow(UUID id, String slug, String name) {}

  private record CachedVerify(ChainVerification verification, OffsetDateTime verifiedAt) {}

  private record LatencyPair(Double avgMs, Double p99Ms) {}

  /** tenant 목록 조회 — admin DataSource auto-commit SELECT. */
  private List<TenantRow> listTenants() {
    return adminJdbc.query(
        LIST_TENANTS_SQL,
        (rs, rowNum) ->
            new TenantRow(
                bytesToUuid(rs.getBytes("id")), rs.getString("slug"), rs.getString("name")));
  }

  /** 캐시에 유효한 결과가 있으면 반환, 없으면 즉시 재검증 후 캐시에 저장. */
  private CachedVerify cachedOrVerify(UUID tenantId) {
    CachedVerify cached = verifyCache.getIfPresent(tenantId);
    if (cached != null) return cached;
    CachedVerify fresh =
        new CachedVerify(verifyTenantWithContext(tenantId), OffsetDateTime.now(ZoneOffset.UTC));
    verifyCache.put(tenantId, fresh);
    return fresh;
  }

  /**
   * {@link AuditService#verifyIntegrity}는 VPD-bound이므로 호출 전 tenant context를 set한다. context는 호출 종료 후
   * 무조건 clear (try/finally).
   */
  private ChainVerification verifyTenantWithContext(UUID tenantId) {
    OffsetDateTime to = OffsetDateTime.now(ZoneOffset.UTC);
    OffsetDateTime from = to.minusDays(30); // 30일 윈도 — UI 모니터링용. scheduler는 daily 24h 범위.
    TenantContextHolder.set(new TenantContext(tenantId, "platform-audit-chain:" + tenantId));
    try {
      return auditService.verifyIntegrity(tenantId, from, to);
    } finally {
      TenantContextHolder.clear();
    }
  }

  /** {@code audit.chain.verify} Timer 스냅샷에서 평균/P99 지연(ms)을 계산한다. */
  private LatencyPair verifyLatency() {
    var timers = meterRegistry.find("audit.chain.verify").timers();
    if (timers.isEmpty()) return new LatencyPair(null, null);

    long totalCount = 0;
    double totalTimeMs = 0;
    Double p99 = null;

    for (Timer t : timers) {
      totalCount += t.count();
      totalTimeMs += t.totalTime(TimeUnit.MILLISECONDS);
      HistogramSnapshot snap = t.takeSnapshot();
      for (ValueAtPercentile v : snap.percentileValues()) {
        if (v.percentile() == 0.99) {
          double ms = v.value(TimeUnit.MILLISECONDS);
          p99 = (p99 == null) ? ms : Math.max(p99, ms);
        }
      }
    }

    Double avg = totalCount == 0 ? null : totalTimeMs / totalCount;
    return new LatencyPair(avg, p99);
  }

  /**
   * 오늘의 03:30 UTC가 아직 지나지 않았으면 오늘 03:30을, 이미 지났으면 내일 03:30을 반환한다. 정각 03:30:00.000은 "지나지 않은" 것으로 처리
   * (isBefore → strictly before).
   */
  private static OffsetDateTime nextDaily0330Utc(OffsetDateTime now) {
    OffsetDateTime today330 = now.withHour(3).withMinute(30).withSecond(0).withNano(0);
    return now.isBefore(today330) ? today330 : today330.plusDays(1);
  }

  /** Oracle RAW(16) 바이트 배열을 UUID로 변환한다. */
  private static UUID bytesToUuid(byte[] bytes) {
    ByteBuffer bb = ByteBuffer.wrap(bytes);
    return new UUID(bb.getLong(), bb.getLong());
  }
}
