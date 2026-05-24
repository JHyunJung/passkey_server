# Platform Activity + Audit Chain Monitor — Phase A (Server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PLATFORM_OPERATOR 전용 cross-tenant 운영 대시보드(Activity)와 SHA-256 hash chain 무결성 모니터(Audit Chain Monitor)를 만들기 위한 서버 endpoint 3개 + 신규 메트릭을 도입한다. 어드민 SPA는 별도 Phase B에서 진행.

**Architecture:** 신규 controller 2개는 `/api/v1/admin/platform/**` 아래에 자리잡고 `@ConditionalOnProperty(passkey.admin.enabled=true)`로 게이트. 데이터 집계는 두 갈래로 나뉜다 — (1) Activity 집계와 Audit Chain status 캐싱은 `adminJdbcTemplate`(APP_ADMIN, EXEMPT ACCESS POLICY)에 native SQL을 직접 던져 VPD를 우회. (2) 실제 hash chain 재검증은 기존 `AuditService.verifyIntegrity`가 VPD-bound이므로 tenant 별로 `TenantContextHolder.set` 후 호출. `AuditEventType`은 신규 `AuditCategory` 매핑을 가진다 — 분류는 서버 단일 진실 원천.

**Tech Stack:** Spring Boot 3.5 / Java 17 / Hibernate JPA / Oracle 19c VPD / Micrometer / Spring Web MVC / Spring Test + Mockito + AssertJ / Caffeine cache / Gradle.

**Spec:** `docs/superpowers/specs/2026-05-24-platform-activity-audit-chain-design.md`

---

## File Map (Phase A 신규/수정)

**Create (8)**
- `server/src/main/java/com/crosscert/passkey/audit/domain/AuditCategory.java`
- `server/src/main/java/com/crosscert/passkey/admin/service/PlatformActivityService.java`
- `server/src/main/java/com/crosscert/passkey/admin/service/PlatformAuditChainService.java`
- `server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformActivityController.java`
- `server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformAuditChainController.java`
- `server/src/test/java/com/crosscert/passkey/unit/audit/domain/AuditCategoryTest.java`
- `server/src/test/java/com/crosscert/passkey/integration/admin/PlatformActivityIntegrationTest.java`
- `server/src/test/java/com/crosscert/passkey/integration/admin/PlatformAuditChainIntegrationTest.java`

**Modify (2)**
- `server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java` — `AuditCategory category` 필드 + 생성자 + `category()` 접근자 + 26개 enum 값에 category 부여
- `server/src/main/java/com/crosscert/passkey/audit/service/AuditService.java` — `Micrometer.Timer audit.chain.verify` 부착

**Run from worktree:** `/Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/platform-activity-audit-chain/server`

---

## Task 1: `AuditCategory` enum 신규

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/audit/domain/AuditCategory.java`

- [ ] **Step 1: Write the enum**

```java
package com.crosscert.passkey.audit.domain;

/**
 * 운영자 UI 필터 칩이 audit 이벤트를 묶기 위해 사용하는 의미적 카테고리. {@link AuditEventType}이 각자 한 값을
 * 가리킨다. 서버가 응답에 미리 채워서 보내므로 클라이언트는 매핑 로직을 갖지 않는다 — single source of truth.
 *
 * <p>세 값의 정의:
 *
 * <ul>
 *   <li>{@link #CEREMONY} — 정상 WebAuthn 등록/인증 경로 + backup-state 전환 같은 부산물 이벤트.
 *   <li>{@link #ADMIN_ACTION} — 운영자(관리자)가 명시적으로 트리거한 변경. RP API 키 발급, tenant 상태 변경,
 *       WebAuthn config 갱신 등.
 *   <li>{@link #SECURITY_FAIL} — 보안 이상 신호. signature counter 회귀, attestation 신뢰 실패, rate-limit
 *       위반, MDS 무효화로 인한 자동 정지/회수.
 * </ul>
 */
public enum AuditCategory {
  CEREMONY,
  ADMIN_ACTION,
  SECURITY_FAIL
}
```

- [ ] **Step 2: Compile**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/audit/domain/AuditCategory.java
git commit -m "feat(audit): AuditCategory enum for cross-tenant activity filter chips"
```

---

## Task 2: `AuditEventType`에 category 부여 (테스트 먼저)

**Files:**
- Create: `server/src/test/java/com/crosscert/passkey/unit/audit/domain/AuditCategoryTest.java`
- Modify: `server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java`

- [ ] **Step 1: Write the failing exhaustive-mapping test**

```java
package com.crosscert.passkey.unit.audit.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.audit.domain.AuditCategory;
import com.crosscert.passkey.audit.domain.AuditEventType;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;

class AuditCategoryTest {

  @Test
  void every_event_type_maps_to_one_category() {
    for (AuditEventType e : AuditEventType.values()) {
      assertThat(e.category())
          .as("AuditEventType.%s 는 category()를 반환해야 한다 (null 금지)", e.name())
          .isNotNull();
    }
  }

  @Test
  void ceremony_events_are_grouped_correctly() {
    EnumSet<AuditEventType> expected =
        EnumSet.of(
            AuditEventType.REGISTRATION_OPTIONS_REQUESTED,
            AuditEventType.CREDENTIAL_REGISTERED,
            AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED,
            AuditEventType.CREDENTIAL_AUTHENTICATED,
            AuditEventType.CREDENTIAL_BACKUP_STATE_CHANGED);
    for (AuditEventType e : AuditEventType.values()) {
      if (e.category() == AuditCategory.CEREMONY) {
        assertThat(expected).contains(e);
      }
    }
    for (AuditEventType e : expected) {
      assertThat(e.category()).isEqualTo(AuditCategory.CEREMONY);
    }
  }

  @Test
  void admin_action_events_are_grouped_correctly() {
    EnumSet<AuditEventType> expected =
        EnumSet.of(
            AuditEventType.TENANT_CREATED,
            AuditEventType.TENANT_SUSPENDED,
            AuditEventType.TENANT_ACTIVATED,
            AuditEventType.API_KEY_ISSUED,
            AuditEventType.API_KEY_REVOKED,
            AuditEventType.WEBAUTHN_CONFIG_UPDATED,
            AuditEventType.ADMIN_USER_CREATED,
            AuditEventType.ADMIN_USER_DELETED,
            AuditEventType.ADMIN_USER_PASSWORD_RESET,
            AuditEventType.CREDENTIAL_REASSIGNED,
            AuditEventType.CREDENTIAL_RENAMED,
            AuditEventType.USER_FORCE_LOGOUT,
            AuditEventType.REFRESH_TOKEN_REVOKED);
    for (AuditEventType e : AuditEventType.values()) {
      if (e.category() == AuditCategory.ADMIN_ACTION) {
        assertThat(expected).contains(e);
      }
    }
    for (AuditEventType e : expected) {
      assertThat(e.category()).isEqualTo(AuditCategory.ADMIN_ACTION);
    }
  }

  @Test
  void security_fail_events_are_grouped_correctly() {
    EnumSet<AuditEventType> expected =
        EnumSet.of(
            AuditEventType.SIGNATURE_COUNTER_REGRESSION,
            AuditEventType.CREDENTIAL_AUTH_RATE_LIMIT,
            AuditEventType.ATTESTATION_TRUST_FAILED,
            AuditEventType.CREDENTIAL_AUTO_SUSPENDED,
            AuditEventType.CREDENTIAL_REVOKED,
            AuditEventType.CREDENTIAL_UNSUSPENDED);
    for (AuditEventType e : AuditEventType.values()) {
      if (e.category() == AuditCategory.SECURITY_FAIL) {
        assertThat(expected).contains(e);
      }
    }
    for (AuditEventType e : expected) {
      assertThat(e.category()).isEqualTo(AuditCategory.SECURITY_FAIL);
    }
  }
}
```

- [ ] **Step 2: Run test to verify it fails (category() does not exist yet)**

Run: `./gradlew test --tests 'com.crosscert.passkey.unit.audit.domain.AuditCategoryTest'`
Expected: COMPILE FAIL — `cannot find symbol: method category()`

- [ ] **Step 3: Modify `AuditEventType` to attach categories**

Open `server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java`. Replace the entire enum body with:

```java
package com.crosscert.passkey.audit.domain;

/**
 * Audit-log event taxonomy. Grouped into five logical sections so that consumers (admin UI filter
 * chips, retention policies, downstream SIEM mappings) can categorize without string matching.
 * Order within each section is stable — append new entries at the end of their group, never
 * renumber.
 *
 * <p>Each value carries an {@link AuditCategory} for the cross-tenant Activity feed filter; that
 * mapping is the single source of truth used both by server aggregations and serialized response
 * payloads.
 */
public enum AuditEventType {

  // ---------- REGISTRATION ----------
  REGISTRATION_OPTIONS_REQUESTED(AuditCategory.CEREMONY),
  CREDENTIAL_REGISTERED(AuditCategory.CEREMONY),

  // ---------- AUTHENTICATION ----------
  AUTHENTICATION_OPTIONS_REQUESTED(AuditCategory.CEREMONY),
  CREDENTIAL_AUTHENTICATED(AuditCategory.CEREMONY),
  SIGNATURE_COUNTER_REGRESSION(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_AUTH_RATE_LIMIT(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_BACKUP_STATE_CHANGED(AuditCategory.CEREMONY),

  // ---------- CREDENTIAL_LIFECYCLE ----------
  CREDENTIAL_REVOKED(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_RENAMED(AuditCategory.ADMIN_ACTION),
  CREDENTIAL_REASSIGNED(AuditCategory.ADMIN_ACTION),
  ATTESTATION_TRUST_FAILED(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_AUTO_SUSPENDED(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_UNSUSPENDED(AuditCategory.SECURITY_FAIL),

  // ---------- ADMIN ----------
  TENANT_CREATED(AuditCategory.ADMIN_ACTION),
  TENANT_SUSPENDED(AuditCategory.ADMIN_ACTION),
  TENANT_ACTIVATED(AuditCategory.ADMIN_ACTION),
  API_KEY_ISSUED(AuditCategory.ADMIN_ACTION),
  API_KEY_REVOKED(AuditCategory.ADMIN_ACTION),
  WEBAUTHN_CONFIG_UPDATED(AuditCategory.ADMIN_ACTION),
  ADMIN_USER_CREATED(AuditCategory.ADMIN_ACTION),
  ADMIN_USER_DELETED(AuditCategory.ADMIN_ACTION),
  ADMIN_USER_PASSWORD_RESET(AuditCategory.ADMIN_ACTION),

  // ---------- SESSION ----------
  USER_FORCE_LOGOUT(AuditCategory.ADMIN_ACTION),
  REFRESH_TOKEN_REVOKED(AuditCategory.ADMIN_ACTION);

  private final AuditCategory category;

  AuditEventType(AuditCategory category) {
    this.category = category;
  }

  public AuditCategory category() {
    return category;
  }
}
```

**Sanity:** the original file groups events under five comment headers (REGISTRATION, AUTHENTICATION, CREDENTIAL_LIFECYCLE, ADMIN, SESSION) — the patch preserves all 25 entries in the same order and only attaches the category argument. Verify by running `git diff server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java` — the diff should be additive (constructor + field + arg per entry) with zero values added/removed/reordered. If the original has a section or entry the spec list missed (e.g. a newer enum value added between the snapshot and now), pick the appropriate category from `AuditCategory` and add it to the relevant grouped EnumSet in `AuditCategoryTest` so the exhaustive check passes.

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests 'com.crosscert.passkey.unit.audit.domain.AuditCategoryTest'`
Expected: 4 tests PASS

- [ ] **Step 5: Run full server unit/slice tests to verify nothing else broke**

Run: `./gradlew test`
Expected: BUILD SUCCESSFUL (단, 통합 테스트는 별도 — task 6 이후 검증)

- [ ] **Step 6: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java \
        server/src/test/java/com/crosscert/passkey/unit/audit/domain/AuditCategoryTest.java
git commit -m "feat(audit): AuditEventType.category() — single source of truth for activity filter chips"
```

---

## Task 3: `audit.chain.verify` Micrometer Timer 부착

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/audit/service/AuditService.java`

- [ ] **Step 1: 현재 AuditService.verifyIntegrity 시그니처 + 의존성 확인**

Run:
```bash
grep -n 'class AuditService\|MeterRegistry\|verifyIntegrity\|Timer\|private final' server/src/main/java/com/crosscert/passkey/audit/service/AuditService.java | head -20
```

Expected: `MeterRegistry`가 이미 주입되어 있을 수 있음 — 있다면 그 인스턴스 재사용. 없으면 생성자 파라미터에 추가.

- [ ] **Step 2: `verifyIntegrity`를 Timer로 감싸는 변경**

기존 `verifyIntegrity` 메서드 위에 클래스 필드를 추가하고 메서드 본문을 `Timer.recordCallable`로 감싼다. 변경 패턴:

```java
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
// 클래스 안:
private final MeterRegistry meterRegistry;

// 생성자에 MeterRegistry 추가 (기존 의존성 보존)

@Transactional(readOnly = true)
public ChainVerification verifyIntegrity(UUID tenantId, OffsetDateTime from, OffsetDateTime to) {
  Timer timer =
      Timer.builder("audit.chain.verify")
          .description("Hash chain re-verification duration per tenant")
          .tag("tenantId", tenantId.toString())
          .register(meterRegistry);
  long startNanos = System.nanoTime();
  try {
    // ... 기존 본문 ...
    return new ChainVerification(tenantId, from, to, ok, tampered);
  } finally {
    timer.record(System.nanoTime() - startNanos, java.util.concurrent.TimeUnit.NANOSECONDS);
  }
}
```

**주의:** `recordCallable`은 checked exception 처리가 까다로워 try/finally + `record(duration)`로 충분. `tag("tenantId", uuid)`는 cardinality가 tenant 수만큼이라 운영 환경 tenant 수가 수백~수천으로 늘면 Prometheus label cardinality 우려가 있으나 본 spec 시점(소수 tenant)에선 OK. Tenant 수가 너무 많아지면 별도 spec에서 tag 제거 또는 sampled tenant id로 전환.

- [ ] **Step 3: Run AuditService 슬라이스/통합 테스트로 회귀 없음 확인**

Run: `./gradlew test --tests '*AuditService*' --tests '*audit.chain*'`
Expected: 기존 테스트 모두 PASS

- [ ] **Step 4: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/audit/service/AuditService.java
git commit -m "feat(audit): Micrometer audit.chain.verify timer on verifyIntegrity"
```

---

## Task 4: `PlatformActivityService` 시그니처 + Summary 집계

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/admin/service/PlatformActivityService.java`

- [ ] **Step 1: 빈 서비스 + record DTO 정의 (컴파일 통과 우선)**

Create file with:

```java
package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.domain.AuditCategory;
import com.crosscert.passkey.audit.domain.AuditEventType;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.distribution.HistogramSnapshot;
import io.micrometer.core.instrument.distribution.ValueAtPercentile;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
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
 * <p>모든 SQL은 {@code APP_ADMIN} (EXEMPT ACCESS POLICY)로 동작하는 {@code adminJdbcTemplate} 위에서
 * 실행되므로 VPD가 tenant predicate를 붙이지 않는다 — cross-tenant 합산이 가능. controller는 {@link
 * com.crosscert.passkey.admin.security.AdminAuthz#requirePlatformOperator()}로 권한을 게이트하고
 * 이 서비스는 권한 검사를 다시 하지 않는다 (이중화 금지).
 *
 * <p>HTTP latency는 Spring Boot Actuator의 {@code http.server.requests} Micrometer 타이머에서 직접
 * snapshot을 읽는다 — Prometheus endpoint 노출 불필요.
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

  // ---- private helpers (다음 step에서 채움) ----

  private long countSince(AuditCategory category, OffsetDateTime since) {
    throw new UnsupportedOperationException("filled in step 3");
  }

  private long countSinceForCategory(AuditCategory category, OffsetDateTime since) {
    throw new UnsupportedOperationException("filled in step 3");
  }

  private LatencySnapshot httpLatencySnapshot() {
    throw new UnsupportedOperationException("filled in step 3");
  }

  private List<TopTenantRow> topTenants(OffsetDateTime since, int limit) {
    throw new UnsupportedOperationException("filled in step 3");
  }

  // feed는 task 5에서 추가
}
```

- [ ] **Step 2: 컴파일 확인**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: helper 메서드 구현 (native SQL + MeterRegistry 추출)**

`PlatformActivityService` 의 `// ---- private helpers` 섹션을 다음으로 교체:

```java
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

  private long countSince(AuditCategory category, OffsetDateTime since) {
    // category == null → 전체 카운트
    if (category == null) {
      return adminJdbc.queryForObject(
          COUNT_TOTAL_SINCE,
          new MapSqlParameterSource().addValue("since", since),
          Long.class);
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
    // Spring Boot Actuator가 자동 등록하는 http.server.requests 타이머의 모든 tag 합산
    var timers = meterRegistry.find("http.server.requests").timers();
    if (timers.isEmpty()) {
      return new LatencySnapshot(null, null, null);
    }
    long totalCount = 0;
    double totalTimeMs = 0;
    // p95/p99는 histogram snapshot에서 — 단일 타이머가 percentile을 노출하지 않으면 null
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
                UUID.fromString(rs.getString("tenant_id")),
                rs.getString("slug"),
                rs.getString("name"),
                rs.getLong("event_count"),
                rs.getLong("active_credentials")));
  }
```

**Important — tenant_id 컬럼 type 주의:** `tenant` 테이블의 `id`는 `RAW(16)`. `rs.getString("tenant_id")`이 정확한 UUID 문자열을 반환하지 않을 수 있다. 만약 통합 테스트(Task 8)에서 매핑이 실패하면 `rs.getObject("tenant_id")` 또는 `rs.getBytes("tenant_id")` 후 `UUID` 변환 헬퍼로 변경. 기존 코드의 패턴 확인:
```bash
grep -rE 'rs\.get.*tenant.?id|tenantIdRowMapper' server/src/main/java --include='*.java' | head
```
패턴이 발견되면 그것을 사용. 없으면 `bytesToUuid(rs.getBytes("tenant_id"))` 헬퍼를 같은 클래스 안에 추가:
```java
private static UUID bytesToUuid(byte[] bytes) {
  java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes);
  return new UUID(bb.getLong(), bb.getLong());
}
```

- [ ] **Step 4: 컴파일**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/admin/service/PlatformActivityService.java
git commit -m "feat(admin): PlatformActivityService — cross-tenant summary aggregation"
```

---

## Task 5: `PlatformActivityService.feed` cursor 페이지네이션

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/admin/service/PlatformActivityService.java`

- [ ] **Step 1: feed 메서드 + cursor 인코딩 추가**

`PlatformActivityService` 끝에 다음 추가:

```java
  private static final int FEED_PAGE_SIZE = 30;

  /**
   * Cross-tenant audit feed. Cursor 기반 페이지네이션으로 새 이벤트가 유입돼도 페이지 경계가 흔들리지 않는다.
   * cursor는 마지막으로 반환된 행의 ({@code createdAt}, {@code id}) — opaque base64 인코딩.
   *
   * <p>{@code category} ∈ {"all", "ceremony", "admin-action", "security-fail"}. {@code tenantIds}가
   * 비어있으면 모든 tenant.
   */
  @Transactional(value = "adminTransactionManager", readOnly = true)
  public FeedPage feed(String cursor, String category, List<UUID> tenantIds) {
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

    // tenant filter
    if (tenantIds != null && !tenantIds.isEmpty()) {
      sql.append("AND a.tenant_id IN (:tenantIds) ");
      // RAW(16) 컬럼이므로 UUID → byte[] 변환
      List<byte[]> rawIds = new ArrayList<>();
      for (UUID id : tenantIds) rawIds.add(uuidToBytes(id));
      params.addValue("tenantIds", rawIds);
    }

    // cursor — (createdAt, id) tuple로 strict-less
    if (cursor != null && !cursor.isBlank()) {
      Cursor c = decodeCursor(cursor);
      sql.append("AND (a.created_at < :curTs OR (a.created_at = :curTs AND a.id < :curId)) ");
      params.addValue("curTs", c.createdAt());
      params.addValue("curId", uuidToBytes(c.id()));
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
    switch (category.toLowerCase()) {
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
    if (sep < 0)
      throw new IllegalArgumentException("invalid cursor");
    return new Cursor(
        OffsetDateTime.parse(raw.substring(0, sep)), UUID.fromString(raw.substring(sep + 1)));
  }

  private static byte[] uuidToBytes(UUID u) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(u.getMostSignificantBits());
    bb.putLong(u.getLeastSignificantBits());
    return bb.array();
  }

  private static UUID bytesToUuid(byte[] bytes) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes);
    return new UUID(bb.getLong(), bb.getLong());
  }
```

**Note:** Task 4의 `topTenants` 도 `rs.getString("tenant_id")` 대신 `bytesToUuid(rs.getBytes("tenant_id"))` 로 같이 수정해야 한다.

- [ ] **Step 2: Task 4의 topTenants 수정**

`topTenants` 메서드의 `UUID.fromString(rs.getString("tenant_id"))` 를 `bytesToUuid(rs.getBytes("tenant_id"))` 로 교체.

- [ ] **Step 3: 컴파일**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/admin/service/PlatformActivityService.java
git commit -m "feat(admin): PlatformActivityService.feed cursor pagination"
```

---

## Task 6: `AdminPlatformActivityController`

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformActivityController.java`

- [ ] **Step 1: Controller 작성**

```java
package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.PlatformActivityService;
import com.crosscert.passkey.admin.service.PlatformActivityService.ActivitySummary;
import com.crosscert.passkey.admin.service.PlatformActivityService.FeedPage;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cross-tenant Activity 페이지 데이터 endpoint. PLATFORM_OPERATOR 전용.
 *
 * <p>{@code @ConditionalOnProperty(passkey.admin.enabled=true)} — admin 콘솔이 배포된 인스턴스에서만
 * 활성. {@link AdminAuthz#requirePlatformOperator()}이 권한 게이트 단일 진입점.
 */
@RestController
@RequestMapping("/api/v1/admin/platform")
@RequiredArgsConstructor
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
@Tag(name = "Admin · Platform · Activity", description = "Cross-tenant activity summary + feed.")
public class AdminPlatformActivityController {

  private final PlatformActivityService activityService;

  @GetMapping("/activity-summary")
  @Operation(
      summary = "Cross-tenant activity summary",
      description =
          "4개 메트릭(활동 24H, 운영 액션, 보안 이벤트, 평균 응답)과 활발한 tenant top-5를 한 응답으로 반환.")
  public ApiResponse<ActivitySummary> summary(
      @RequestParam(name = "window", defaultValue = "24h") String window) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(activityService.summary(window));
  }

  @GetMapping("/activity-feed")
  @Operation(
      summary = "Cross-tenant audit feed",
      description =
          "cursor 기반 페이지네이션. category ∈ {all, ceremony, admin-action, security-fail}. "
              + "tenantIds 미지정 시 전체.")
  public ApiResponse<FeedPage> feed(
      @RequestParam(name = "cursor", required = false) String cursor,
      @RequestParam(name = "category", defaultValue = "all") String category,
      @RequestParam(name = "tenantIds", required = false) List<UUID> tenantIds) {
    AdminAuthz.requirePlatformOperator();
    List<UUID> ids = tenantIds == null ? new ArrayList<>() : tenantIds;
    return ApiResponse.ok(activityService.feed(cursor, category, ids));
  }
}
```

- [ ] **Step 2: 컴파일**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformActivityController.java
git commit -m "feat(admin): AdminPlatformActivityController — /platform/activity-summary + /activity-feed"
```

---

## Task 7: `PlatformAuditChainService.status()` 와 `verifyAll()`

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/admin/service/PlatformAuditChainService.java`

- [ ] **Step 1: 빈 서비스 + DTO 정의**

```java
package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.audit.service.AuditService.ChainVerification;
import com.crosscert.passkey.common.tenant.TenantContext;
import com.crosscert.passkey.common.tenant.TenantContextHolder;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.distribution.HistogramSnapshot;
import io.micrometer.core.instrument.distribution.ValueAtPercentile;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Cross-tenant audit hash-chain 무결성 모니터링 데이터 + 즉시 검증 orchestrator.
 *
 * <p>두 가지 DB 경로를 혼합한다. (a) tenant 목록 / verifier 메트릭 / 마지막 verify 결과 캐싱은 {@code
 * adminJdbcTemplate} (APP_ADMIN, VPD exempt). (b) 실제 hash chain 재검증은 {@link
 * AuditService#verifyIntegrity}가 VPD-bound 이므로 tenant별로 {@link TenantContextHolder#set} 후 호출.
 *
 * <p>status() 결과는 {@link Caffeine} 캐시(TTL 60s)에 저장 — 사용자 polling 주기와 동기. verifyAll() 호출은
 * 캐시를 무효화하고 모든 tenant를 직렬 재검증.
 */
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class PlatformAuditChainService {

  public record TenantChainRow(
      UUID tenantId,
      String slug,
      String name,
      String status, // "INTACT" | "TAMPERED"
      long verifiedRows,
      OffsetDateTime lastVerifiedAt,
      int tamperedRowCount) {}

  public record TamperedTenantSummary(
      UUID tenantId, String slug, String name, int tamperedRowCount, OffsetDateTime lastVerifiedAt) {}

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

  private static final String LIST_TENANTS_SQL =
      "SELECT id, slug, name FROM tenant ORDER BY name ASC";

  private final NamedParameterJdbcTemplate adminJdbc;
  private final AuditService auditService;
  private final MeterRegistry meterRegistry;

  /** {@code tenantId → last verify result + timestamp}. TTL 60s. */
  private final Cache<UUID, CachedVerify> verifyCache =
      Caffeine.newBuilder().expireAfterWrite(Duration.ofSeconds(60)).maximumSize(10_000).build();

  private record CachedVerify(ChainVerification verification, OffsetDateTime verifiedAt) {}

  public PlatformAuditChainService(
      NamedParameterJdbcTemplate adminJdbcTemplate,
      AuditService auditService,
      MeterRegistry meterRegistry) {
    this.adminJdbc = adminJdbcTemplate;
    this.auditService = auditService;
    this.meterRegistry = meterRegistry;
  }

  // ---- public API ----

  public ChainStatus status() {
    List<TenantRow> tenants = listTenants();
    List<TenantChainRow> perTenant = new ArrayList<>();
    List<TamperedTenantSummary> tampered = new ArrayList<>();
    int intact = 0;
    long totalVerified = 0;
    for (TenantRow t : tenants) {
      ChainVerification ver = cachedOrVerify(t.id());
      int tamperCount = ver.tamperedEntryIds().size();
      String statusStr = ver.intact() ? "INTACT" : "TAMPERED";
      OffsetDateTime verifiedAt = verifyCache.getIfPresent(t.id()).verifiedAt();
      perTenant.add(
          new TenantChainRow(
              t.id(), t.slug(), t.name(), statusStr, ver.verifiedRows(), verifiedAt, tamperCount));
      if (ver.intact()) {
        intact++;
      } else {
        tampered.add(new TamperedTenantSummary(t.id(), t.slug(), t.name(), tamperCount, verifiedAt));
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

  public VerifyAllResult verifyAll() {
    OffsetDateTime started = OffsetDateTime.now(ZoneOffset.UTC);
    List<TenantRow> tenants = listTenants();
    List<VerifyTenantResult> results = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    int intact = 0;
    int tampered = 0;
    for (TenantRow t : tenants) {
      long start = System.nanoTime();
      try {
        ChainVerification ver = verifyTenantWithContext(t.id());
        verifyCache.put(t.id(), new CachedVerify(ver, OffsetDateTime.now(ZoneOffset.UTC)));
        long ms = (System.nanoTime() - start) / 1_000_000;
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
    return new VerifyAllResult(started, completed, tenants.size(), intact, tampered, results, errors);
  }

  // ---- private helpers ----

  private record TenantRow(UUID id, String slug, String name) {}

  @Transactional(value = "adminTransactionManager", readOnly = true)
  protected List<TenantRow> listTenants() {
    return adminJdbc.query(
        LIST_TENANTS_SQL,
        (rs, rowNum) ->
            new TenantRow(
                bytesToUuid(rs.getBytes("id")), rs.getString("slug"), rs.getString("name")));
  }

  private ChainVerification cachedOrVerify(UUID tenantId) {
    CachedVerify cached = verifyCache.getIfPresent(tenantId);
    if (cached != null) return cached.verification();
    ChainVerification fresh = verifyTenantWithContext(tenantId);
    verifyCache.put(tenantId, new CachedVerify(fresh, OffsetDateTime.now(ZoneOffset.UTC)));
    return fresh;
  }

  /**
   * {@link AuditService#verifyIntegrity}는 VPD-bound이므로 호출 전 tenant context를 set한다. context는
   * 호출 끝나면 무조건 clear (try/finally).
   */
  private ChainVerification verifyTenantWithContext(UUID tenantId) {
    OffsetDateTime to = OffsetDateTime.now(ZoneOffset.UTC);
    OffsetDateTime from = to.minusDays(30); // 30일 윈도 — scheduler와 동등 범위
    TenantContextHolder.set(new TenantContext(tenantId, "platform-audit-chain:" + tenantId));
    try {
      return auditService.verifyIntegrity(tenantId, from, to);
    } finally {
      TenantContextHolder.clear();
    }
  }

  private LatencyPair verifyLatency() {
    var timers = meterRegistry.find("audit.chain.verify").timers();
    if (timers.isEmpty()) return new LatencyPair(null, null);
    long totalCount = 0;
    double totalTimeMs = 0;
    Double p99 = null;
    for (Timer t : timers) {
      totalCount += t.count();
      totalTimeMs += t.totalTime(java.util.concurrent.TimeUnit.MILLISECONDS);
      HistogramSnapshot snap = t.takeSnapshot();
      for (ValueAtPercentile v : snap.percentileValues()) {
        if (v.percentile() == 0.99) {
          double ms = v.value(java.util.concurrent.TimeUnit.MILLISECONDS);
          p99 = (p99 == null) ? ms : Math.max(p99, ms);
        }
      }
    }
    Double avg = totalCount == 0 ? null : totalTimeMs / totalCount;
    return new LatencyPair(avg, p99);
  }

  private record LatencyPair(Double avgMs, Double p99Ms) {}

  private static OffsetDateTime nextDaily0330Utc(OffsetDateTime now) {
    OffsetDateTime today330 =
        now.withHour(3).withMinute(30).withSecond(0).withNano(0);
    return now.isBefore(today330) ? today330 : today330.plusDays(1);
  }

  private static UUID bytesToUuid(byte[] bytes) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes);
    return new UUID(bb.getLong(), bb.getLong());
  }
}
```

**Verify:** `TenantContext` 클래스명/패키지가 위 import (`com.crosscert.passkey.common.tenant.TenantContext`)와 맞는지 확인:
```bash
grep -rE 'class TenantContext\b|record TenantContext\b' server/src/main/java --include='*.java' | head
```
만약 패키지가 다르면 import 경로를 그것에 맞춘다. `TenantContextHolder.set`이 받는 인자 타입도 같은 방법으로 확인.

- [ ] **Step 2: 컴파일**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/admin/service/PlatformAuditChainService.java
git commit -m "feat(admin): PlatformAuditChainService — cached status + serial verifyAll"
```

---

## Task 8: `AdminPlatformAuditChainController`

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformAuditChainController.java`

- [ ] **Step 1: Controller 작성**

```java
package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.PlatformAuditChainService;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.ChainStatus;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.VerifyAllResult;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cross-tenant SHA-256 hash chain 무결성 모니터링 endpoint. PLATFORM_OPERATOR 전용.
 *
 * <p>{@link #status()}는 캐시된 결과를 빠르게 반환(TTL 60s). {@link #verifyAll()}은 모든 tenant를 직렬로
 * 즉시 재검증 — 호출 비용이 크니 사용자 액션(버튼)에만 노출.
 */
@RestController
@RequestMapping("/api/v1/admin/platform/audit-chain")
@RequiredArgsConstructor
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
@Tag(
    name = "Admin · Platform · Audit Chain",
    description = "Cross-tenant audit hash chain status + on-demand verify.")
public class AdminPlatformAuditChainController {

  private final PlatformAuditChainService chainService;

  @GetMapping("/status")
  @Operation(
      summary = "Audit chain status",
      description = "모든 tenant의 마지막 검증 결과 합산. 캐시 TTL 60s.")
  public ApiResponse<ChainStatus> status() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(chainService.status());
  }

  @PostMapping("/verify")
  @Operation(
      summary = "Verify all tenants now",
      description =
          "모든 ACTIVE tenant의 hash chain을 직렬 재검증 후 동기 응답. 실패한 tenant는 errors[]에 보고, "
              + "나머지 결과는 정상 포함.")
  public ApiResponse<VerifyAllResult> verifyAll() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(chainService.verifyAll());
  }
}
```

- [ ] **Step 2: 컴파일**

Run: `./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: 슬라이스 테스트 회귀 없음 (전체 unit/slice)**

Run: `./gradlew test`
Expected: BUILD SUCCESSFUL — 통합 테스트는 별도 다음 task에서

- [ ] **Step 4: Commit**

```bash
git add server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformAuditChainController.java
git commit -m "feat(admin): AdminPlatformAuditChainController — /platform/audit-chain/status + /verify"
```

---

## Task 9: `PlatformActivityIntegrationTest` (cross-tenant + VPD positive)

**Files:**
- Create: `server/src/test/java/com/crosscert/passkey/integration/admin/PlatformActivityIntegrationTest.java`

- [ ] **Step 1: 통합 테스트 작성**

레퍼런스로 `AdminPlatformStatsIntegrationTest.java`의 seed 패턴을 따른다 (admin 데이터소스에 직접 INSERT). 위치:
```bash
ls server/src/test/java/com/crosscert/passkey/integration/admin/
head -40 server/src/test/java/com/crosscert/passkey/integration/admin/AdminPlatformStatsIntegrationTest.java
```

새 파일:

```java
package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.admin.service.PlatformActivityService;
import com.crosscert.passkey.admin.service.PlatformActivityService.ActivitySummary;
import com.crosscert.passkey.admin.service.PlatformActivityService.FeedPage;
import com.crosscert.passkey.audit.domain.AuditCategory;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * 4개 tenant seed 후 cross-tenant 합산 + VPD 우회가 실제로 작동하는지 검증. 좋은 통합 테스트는 두 가지를
 * 동시에 보여야 한다 — (1) 다른 tenant 데이터가 응답에 섞여 들어오는 positive case, (2) 다른 tenant의
 * audit row가 누락되거나 카테고리 분류가 빗나가지 않는 부정 case.
 */
class PlatformActivityIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired private PlatformActivityService service;
  @Autowired private TenantSeed tenantSeed;

  @Autowired
  @Qualifier("adminDataSource")
  private DataSource adminDataSource;

  private NamedParameterJdbcTemplate adminJdbc;

  @BeforeEach
  void setupJdbc() {
    adminJdbc = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void summary_aggregates_events_across_all_seeded_tenants() {
    UUID t1 = tenantSeed.create("activity-a");
    UUID t2 = tenantSeed.create("activity-b");
    UUID t3 = tenantSeed.create("activity-c");
    UUID t4 = tenantSeed.create("activity-d");

    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    // 24h window 안의 이벤트 — 3개 카테고리 각각 1건씩, 4개 tenant 분산
    insertAuditRow(t1, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusHours(1));
    insertAuditRow(t2, AuditEventType.API_KEY_ISSUED, now.minusHours(2));
    insertAuditRow(t3, AuditEventType.SIGNATURE_COUNTER_REGRESSION, now.minusHours(3));
    insertAuditRow(t4, AuditEventType.CREDENTIAL_REGISTERED, now.minusHours(4));
    // 24h 밖 — 합산에서 빠져야 함
    insertAuditRow(t1, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusHours(48));

    ActivitySummary baseline = service.summary("24h");
    // 4건 추가 → 4 이상 (다른 테스트 잔여물은 + 더 있을 수 있음)
    assertThat(baseline.activity24h()).isGreaterThanOrEqualTo(4);
    assertThat(baseline.adminMutations24h()).isGreaterThanOrEqualTo(1); // API_KEY_ISSUED
    assertThat(baseline.securityEvents24h()).isGreaterThanOrEqualTo(1); // SIGNATURE_COUNTER_REGRESSION

    // top tenants — seed한 tenant가 결과 안에 있는지 (조용한 다른 tenant보다 위)
    List<UUID> topIds = baseline.topTenants().stream().map(r -> r.tenantId()).toList();
    assertThat(topIds).contains(t1);
  }

  @Test
  void feed_returns_items_from_multiple_tenants_with_correct_categories() {
    UUID t1 = tenantSeed.create("feed-a");
    UUID t2 = tenantSeed.create("feed-b");
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    insertAuditRow(t1, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusMinutes(1));
    insertAuditRow(t2, AuditEventType.API_KEY_ISSUED, now.minusMinutes(2));

    FeedPage page = service.feed(null, "all", List.of(t1, t2));

    assertThat(page.items()).hasSizeGreaterThanOrEqualTo(2);
    assertThat(page.items().stream().map(i -> i.tenantId()))
        .as("응답에 두 tenant가 모두 등장")
        .contains(t1, t2);
    // category가 enum source-of-truth와 일치
    for (var item : page.items()) {
      assertThat(item.category()).isEqualTo(item.eventType().category());
    }
  }

  @Test
  void feed_filter_by_category_returns_only_admin_actions() {
    UUID t = tenantSeed.create("feed-cat");
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    insertAuditRow(t, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusMinutes(1)); // CEREMONY
    insertAuditRow(t, AuditEventType.API_KEY_ISSUED, now.minusMinutes(2)); // ADMIN_ACTION

    FeedPage page = service.feed(null, "admin-action", List.of(t));

    assertThat(page.items())
        .as("category=admin-action 필터에 ADMIN_ACTION만")
        .allMatch(i -> i.category() == AuditCategory.ADMIN_ACTION);
  }

  @Test
  void feed_cursor_pagination_returns_consistent_window() {
    UUID t = tenantSeed.create("feed-cursor");
    OffsetDateTime base = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(60);
    for (int i = 0; i < 35; i++) {
      insertAuditRow(t, AuditEventType.CREDENTIAL_AUTHENTICATED, base.plusSeconds(i));
    }

    FeedPage first = service.feed(null, "all", List.of(t));
    assertThat(first.items()).hasSize(30);
    assertThat(first.nextCursor()).isNotNull();

    FeedPage second = service.feed(first.nextCursor(), "all", List.of(t));
    assertThat(second.items()).hasSizeGreaterThanOrEqualTo(5);
    // 페이지 경계가 중복되지 않는다 — 첫 페이지 마지막 id ≠ 두 번째 페이지 첫 id
    UUID lastOfFirst = first.items().get(first.items().size() - 1).id();
    UUID firstOfSecond = second.items().get(0).id();
    assertThat(lastOfFirst).isNotEqualTo(firstOfSecond);
  }

  // ---- helpers ----

  private void insertAuditRow(UUID tenantId, AuditEventType type, OffsetDateTime when) {
    // audit_log 스키마는 V1__oracle_baseline.sql 참조 — id RAW(16), tenant_id RAW(16),
    // event_type VARCHAR2, payload CLOB, prev_hash + row_hash VARCHAR2, created_at TIMESTAMP WITH TZ,
    // actor_type / actor_id / subject_type / subject_id 등.
    // 통합 테스트는 hash chain 적법성을 강제하지 않으므로 prev_hash/row_hash는 dummy로 채운다.
    adminJdbc.update(
        "INSERT INTO audit_log "
            + "(id, tenant_id, event_type, payload, prev_hash, row_hash, created_at, "
            + " actor_type, actor_id, subject_type, subject_id) "
            + "VALUES (:id, :tid, :type, '{}', 'prev', 'row', :ts, "
            + "        'END_USER', 'actor-001', 'CREDENTIAL', 'subject-001')",
        new MapSqlParameterSource()
            .addValue("id", uuidToBytes(UUID.randomUUID()))
            .addValue("tid", uuidToBytes(tenantId))
            .addValue("type", type.name())
            .addValue("ts", when));
  }

  private static byte[] uuidToBytes(UUID u) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(u.getMostSignificantBits());
    bb.putLong(u.getLeastSignificantBits());
    return bb.array();
  }
}
```

**Important — audit_log 컬럼 검증:** 위 INSERT의 컬럼 목록과 NOT NULL 제약은 실제 schema와 정확히 맞춰야 한다. V1 baseline에서 audit_log 정의를 먼저 본다:
```bash
grep -A 30 'CREATE TABLE.*audit_log\|create table.*audit_log' server/src/main/resources/db/migration/V1__oracle_baseline.sql
```
만약 NOT NULL 컬럼이 위 INSERT에 빠져 있으면 추가. 만약 `actor_id` 가 RAW(16) 이라 string으로 INSERT가 거부되면 `null`로 두고 `actor_type` 만 채우거나 byte array로 변환.

**Important — TenantSeed.create 시그니처:** `TenantSeed`가 `create(String slug)` → `UUID` 형태인지, 아니면 `create(name, slug)` 인지 확인:
```bash
head -40 server/src/test/java/com/crosscert/passkey/integration/support/TenantSeed.java
```
시그니처에 맞춰 호출부 교체.

- [ ] **Step 2: 통합 테스트 실행**

Run: `./gradlew test --tests 'com.crosscert.passkey.integration.admin.PlatformActivityIntegrationTest'`
Expected: 4 tests PASS

- [ ] **Step 3: Commit**

```bash
git add server/src/test/java/com/crosscert/passkey/integration/admin/PlatformActivityIntegrationTest.java
git commit -m "test(admin): PlatformActivityIntegrationTest — cross-tenant summary + feed + cursor"
```

---

## Task 10: `PlatformAuditChainIntegrationTest`

**Files:**
- Create: `server/src/test/java/com/crosscert/passkey/integration/admin/PlatformAuditChainIntegrationTest.java`

- [ ] **Step 1: 통합 테스트 작성**

```java
package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.admin.service.PlatformAuditChainService;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.ChainStatus;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.VerifyAllResult;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.tenant.TenantContext;
import com.crosscert.passkey.common.tenant.TenantContextHolder;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * cross-tenant audit chain 상태 집계 + verifyAll() 직렬 검증을 실제 Oracle 위에서 실행. 한 tenant의 audit
 * 행 hash를 인위적으로 깨뜨려 tampered tenant가 응답에 등장하는지, 다른 tenant는 영향이 없는지 확인한다.
 */
class PlatformAuditChainIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired private PlatformAuditChainService chainService;
  @Autowired private AuditService auditService;
  @Autowired private TenantSeed tenantSeed;

  @Autowired
  @Qualifier("adminDataSource")
  private DataSource adminDataSource;

  private NamedParameterJdbcTemplate adminJdbc;

  @BeforeEach
  void setupJdbc() {
    adminJdbc = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void status_marks_tampered_tenant_and_keeps_others_intact() {
    UUID intactTenant = tenantSeed.create("chain-intact");
    UUID tamperedTenant = tenantSeed.create("chain-tampered");

    // 정상 audit row — auditService.append가 hash chain을 자기 일관성 있게 채운다
    TenantContextHolder.set(new TenantContext(intactTenant, "test"));
    try {
      auditService.append(
          AuditEventType.CREDENTIAL_REGISTERED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          "actor-1",
          "CREDENTIAL",
          "subj-1",
          Map.of());
    } finally {
      TenantContextHolder.clear();
    }
    TenantContextHolder.set(new TenantContext(tamperedTenant, "test"));
    try {
      auditService.append(
          AuditEventType.CREDENTIAL_REGISTERED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          "actor-2",
          "CREDENTIAL",
          "subj-2",
          Map.of());
    } finally {
      TenantContextHolder.clear();
    }

    // tamperedTenant의 row_hash 손상
    adminJdbc.update(
        "UPDATE audit_log SET row_hash = 'corrupted' WHERE tenant_id = :tid",
        new MapSqlParameterSource().addValue("tid", uuidToBytes(tamperedTenant)));

    ChainStatus status = chainService.status();

    assertThat(status.tamperedTenants())
        .as("tamperedTenants에 손상된 tenant만 등장")
        .anyMatch(s -> s.tenantId().equals(tamperedTenant))
        .noneMatch(s -> s.tenantId().equals(intactTenant));
    assertThat(status.perTenant())
        .filteredOn(r -> r.tenantId().equals(intactTenant))
        .singleElement()
        .satisfies(r -> assertThat(r.status()).isEqualTo("INTACT"));
    assertThat(status.perTenant())
        .filteredOn(r -> r.tenantId().equals(tamperedTenant))
        .singleElement()
        .satisfies(r -> assertThat(r.status()).isEqualTo("TAMPERED"));
  }

  @Test
  void verifyAll_returns_per_tenant_results_including_tampered() {
    UUID intactTenant = tenantSeed.create("verify-intact");
    UUID tamperedTenant = tenantSeed.create("verify-tampered");

    TenantContextHolder.set(new TenantContext(intactTenant, "test"));
    try {
      auditService.append(
          AuditEventType.CREDENTIAL_REGISTERED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          "actor-a",
          "CREDENTIAL",
          "subj-a",
          Map.of());
    } finally {
      TenantContextHolder.clear();
    }
    TenantContextHolder.set(new TenantContext(tamperedTenant, "test"));
    try {
      auditService.append(
          AuditEventType.CREDENTIAL_REGISTERED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          "actor-b",
          "CREDENTIAL",
          "subj-b",
          Map.of());
    } finally {
      TenantContextHolder.clear();
    }
    adminJdbc.update(
        "UPDATE audit_log SET row_hash = 'corrupted' WHERE tenant_id = :tid",
        new MapSqlParameterSource().addValue("tid", uuidToBytes(tamperedTenant)));

    VerifyAllResult result = chainService.verifyAll();

    assertThat(result.tenantsChecked()).isGreaterThanOrEqualTo(2);
    assertThat(result.perTenant())
        .filteredOn(r -> r.tenantId().equals(intactTenant))
        .singleElement()
        .satisfies(r -> assertThat(r.intact()).isTrue());
    assertThat(result.perTenant())
        .filteredOn(r -> r.tenantId().equals(tamperedTenant))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.intact()).isFalse();
              assertThat(r.tamperedRowCount()).isGreaterThanOrEqualTo(1);
            });
  }

  private static byte[] uuidToBytes(UUID u) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(u.getMostSignificantBits());
    bb.putLong(u.getLeastSignificantBits());
    return bb.array();
  }
}
```

**Verify AuditService.append signature:** 시그니처가 본 plan 가정(`EventType, ActorType, actorId, subjectType, subjectId, payloadMap`)과 정확히 일치하는지 확인:
```bash
grep -A4 'public .* append(' server/src/main/java/com/crosscert/passkey/audit/service/AuditService.java | head -20
```
실제 시그니처가 다르면 호출부 6개를 그것에 맞춤. `ActorType` enum 패키지도 확인.

- [ ] **Step 2: 통합 테스트 실행**

Run: `./gradlew test --tests 'com.crosscert.passkey.integration.admin.PlatformAuditChainIntegrationTest'`
Expected: 2 tests PASS

- [ ] **Step 3: Commit**

```bash
git add server/src/test/java/com/crosscert/passkey/integration/admin/PlatformAuditChainIntegrationTest.java
git commit -m "test(admin): PlatformAuditChainIntegrationTest — tampered detection + verifyAll"
```

---

## Task 11: 전체 `./gradlew check` + spotless + ArchUnit

**Files:** (코드 변경 없음 — 게이트만)

- [ ] **Step 1: spotlessApply (스타일 자동 정리)**

Run: `./gradlew spotlessApply`
Expected: BUILD SUCCESSFUL

- [ ] **Step 2: 변경된 파일이 있으면 commit**

```bash
git status --short
```
변경이 보이면:
```bash
git add -u
git commit -m "style: spotlessApply"
```

- [ ] **Step 3: 전체 check (PR 게이트와 동일)**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL — slice + integration + ArchUnit + spotlessCheck 모두 통과

ArchUnit 실패 가능 케이스:
- Rule 2 (TenantContextHolder 호출 허용 목록) — `PlatformAuditChainService`가 호출하므로 `PackageArchitectureTest`의 allow-list에 추가 필요할 수 있다. 실패 시 그 테스트의 Rule 2 패키지/클래스 목록에 `PlatformAuditChainService` 추가.
- Rule 5/6 (`/api/v1/admin/**` prefix + `AdminAuthz` 호출) — controller가 이미 `/api/v1/admin/platform/**` 사용 + `requirePlatformOperator()` 호출하므로 통과 예상.

- [ ] **Step 4: ArchUnit 갱신이 필요했다면 commit**

```bash
git add -u
git commit -m "test(arch): allow PlatformAuditChainService to set TenantContextHolder"
```

---

## Task 12: 수동 sanity — 서버 부팅 + 엔드포인트 200 응답

**Files:** (코드 변경 없음 — 수동 확인)

- [ ] **Step 1: 서버 부팅**

Run:
```bash
./gradlew bootRun --args='--spring.profiles.active=local --passkey.admin.enabled=true'
```
백그라운드. `actuator/health` 200 OK 확인.

- [ ] **Step 2: dev admin 로그인 + CSRF 토큰 확보**

```bash
rm -f /tmp/cookies.txt
curl -s -c /tmp/cookies.txt -o /dev/null -H 'Origin: http://localhost:5173' http://localhost:8080/api/v1/admin/me
CSRF=$(awk '$6=="XSRF-TOKEN" {print $7}' /tmp/cookies.txt | tail -1)
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -H "X-XSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' -H 'Origin: http://localhost:5173' \
  -X POST http://localhost:8080/api/v1/admin/auth/login \
  -d '{"email":"dev@local.test","password":"devpassword!"}'
CSRF=$(awk '$6=="XSRF-TOKEN" {print $7}' /tmp/cookies.txt | tail -1)
```

- [ ] **Step 3: 3개 endpoint 호출 + 200 + 필수 필드 확인**

```bash
echo '=== activity-summary ==='
curl -s -b /tmp/cookies.txt -H "X-XSRF-TOKEN: $CSRF" -H 'Origin: http://localhost:5173' \
  http://localhost:8080/api/v1/admin/platform/activity-summary | python3 -m json.tool

echo '=== activity-feed ==='
curl -s -b /tmp/cookies.txt -H "X-XSRF-TOKEN: $CSRF" -H 'Origin: http://localhost:5173' \
  http://localhost:8080/api/v1/admin/platform/activity-feed | python3 -m json.tool

echo '=== audit-chain/status ==='
curl -s -b /tmp/cookies.txt -H "X-XSRF-TOKEN: $CSRF" -H 'Origin: http://localhost:5173' \
  http://localhost:8080/api/v1/admin/platform/audit-chain/status | python3 -m json.tool
```

Expected:
- 모두 `"success": true`
- summary는 `activity24h`, `adminMutations24h`, `securityEvents24h`, `latency`, `topTenants` 필드 존재
- feed는 `items`, `nextCursor` 존재 (items는 빈 배열일 수 있음)
- status는 `totalTenants`, `intactTenants`, `tamperedTenants`, `perTenant`, `schedulerCron`, `adminPollingIntervalSec=60` 존재

- [ ] **Step 4: 서버 종료**

```bash
PIDS=$(lsof -nP -iTCP:8080 -sTCP:LISTEN -t 2>/dev/null)
[ -n "$PIDS" ] && kill $PIDS
```

- [ ] **Step 5: README 또는 docs 업데이트는 Phase B에서 진행 — 본 Phase는 백엔드 only이므로 별도 docs 변경 없음**

---

## Self-Review Checklist (자동 — Phase A 종료 시점)

**Spec coverage**:
- §3.2 activity-summary endpoint → Task 4, 6
- §3.2 activity-feed endpoint → Task 5, 6
- §3.2 audit-chain/status endpoint → Task 7, 8
- §3.2 audit-chain/verify endpoint → Task 7, 8
- §3.3 메트릭 — http.server.requests → Task 4 (httpLatencySnapshot)
- §3.3 메트릭 — audit.chain.verify → Task 3
- §4.1 AuditEventType.category() → Task 2
- §4.2 PlatformAuditChainService (Caffeine 캐시, 직렬 verifyAll) → Task 7
- §4.3 PlatformActivityService → Task 4, 5
- §4.4 controller 2개 → Task 6, 8
- §7 서버 테스트 (unit, slice, integration) → Task 2, 9, 10
- §8 Phase A 롤아웃 모든 단계 커버

**Placeholder 스캔**: TBD/TODO 0건. 모든 step에 실행 가능한 코드/명령. 단, 코드 작성 중 마주칠 수 있는 두 가지 환경 의존 사항(예: tenant_id 컬럼이 RAW 인지 STRING 인지, AuditService.append 시그니처)은 step 안에 검증 명령과 fallback 처리를 명시.

**Type consistency**: ChainVerification은 기존 record를 그대로 사용. PlatformAuditChainService의 내부 record들(ChainStatus, TenantChainRow 등)은 같은 파일 안에서 일관. 모든 cursor encoding 함수는 같은 파일 안.

**Scope**: 본 plan은 백엔드 단독 (Phase B 어드민 SPA는 별도 plan). 12개 task, 평균 작은 단위. TDD: Task 2 (unit), Task 9-10 (integration)가 빨간 → 초록 패턴.
