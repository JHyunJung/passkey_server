# Platform Activity + Audit Chain Monitor — Design

**Date**: 2026-05-24
**Scope**: 2개 PLATFORM_OPERATOR 전용 화면을 한 번에 도입. 기존 사이드바의 mock URL을 실제 페이지로 교체.
**Status**: Design (awaiting approval)

## 1. 배경 / 동기

현재 admin SPA의 사이드바 좌측에는 `Activity` / `Audit Chain` 두 항목이 이미 존재하지만 라우트가 `/console#me=platform&name=activity` 같은 mock URL이라 실제 페이지가 없다. 두 mockup이 화면 시안 수준으로 잡혀있고 운영 콘솔의 "골든 패스"를 형성한다:

- **Activity** — 운영자가 "지금 무슨 일이 일어나고 있나"를 한 화면에서 본다. 사고/장애 1차 대응의 진입점.
- **Audit Chain Monitor** — 보안 컴플라이언스의 핵심. tenant별 SHA-256 hash chain 무결성 상태를 한눈에 보고, 위변조 의심이 뜨면 즉시 대응한다.

서버는 per-tenant audit / verify endpoint를 갖고 있지만 cross-tenant 집계는 없다. 본 spec은 두 화면을 만들기 위한 서버 endpoint 3개 + admin 페이지 2개 + 신규 메트릭 1종을 정의한다.

## 2. 비대상 (YAGNI)

다음은 본 spec 범위에서 명시적으로 제외하며, 필요해지면 별도 spec으로 다룬다.

- PDF 보고서 (CSV만 지원)
- WebSocket / SSE 실시간 푸시 (polling만)
- "Incident 생성" 외부 ticket 시스템 통합 (placeholder 버튼만 — 클릭 시 안내)
- ⌘K 글로벌 검색바
- Mini chart sparkline
- 시간대별 chain 누적 추이 차트
- scheduler_lease 직접 노출

## 3. 아키텍처

### 3.1 위치
- Admin SPA 신규 라우트 2개:
  - `/platform/activity` — 사이드바 "Activity" 항목의 라우트로 교체
  - `/platform/audit-chain` — 사이드바 "Audit Chain" 항목의 라우트로 교체
- 두 화면 모두 PLATFORM_OPERATOR 전용. RP_ADMIN 역할에서는 사이드바 항목 자체가 hide되고, 직접 URL 입력해도 라우트 가드가 403/redirect.

### 3.2 서버 신규 endpoint (모두 ⭐ PLATFORM_OPERATOR 게이트)

#### `GET /api/v1/admin/platform/activity-summary?window=24h`
- 4개 메트릭 카드 + 활발한 tenant Top-5 패널을 한 요청으로 충족.
- 응답:
  ```json
  {
    "window": "24h",
    "activity24h": 20898,
    "adminMutations24h": 9,
    "securityEvents24h": 18,
    "latency": { "avgMs": 18, "p95Ms": 42, "p99Ms": 89 },
    "topTenants": [
      { "tenantId": "uuid", "slug": "acme", "name": "Acme Corp",
        "eventCount24h": 2322, "activeCredentials": 14823 }
    ]
  }
  ```
- `window`는 현재 `24h` 고정. 미래 확장 위해 query param으로 둠.

#### `GET /api/v1/admin/platform/activity-feed?cursor=&category=&tenantIds=`
- cross-tenant audit 피드.
- `category` ∈ `{all, ceremony, admin-action, security-fail}`.
- `tenantIds` 쉼표 구분 multi-value.
- cursor 기반 페이지네이션 (page-offset 아님 — 새 이벤트 유입에 안전).
- 응답:
  ```json
  {
    "items": [
      { "id": "audit-row-id",
        "createdAt": "2026-05-24T11:32:15Z",
        "eventType": "CREDENTIAL_AUTHENTICATED",
        "category": "ceremony",
        "tenantId": "uuid", "tenantName": "Acme Corp",
        "actorType": "END_USER", "actorIdShort": "k_aB3xY7Q9",
        "subjectType": "CREDENTIAL", "subjectIdShort": "Tg2hPq7vN3jL" }
    ],
    "nextCursor": "opaque-string-or-null"
  }
  ```
- 서버가 actor/subject ID를 앞 12자까지만 잘라 반환. 전체 ID가 필요하면 클릭 시 audit row 상세 별도 조회 (이미 존재하는 `/audit-logs/{id}` 미존재 — Phase B에서 필요 시 추가, 본 spec MVP에선 short ID만 표시).

#### `GET /api/v1/admin/platform/audit-chain/status`
- 4개 메트릭 카드 + 알림 배너 + 테이블을 한 요청으로 충족.
- 응답:
  ```json
  {
    "totalTenants": 9,
    "intactTenants": 8,
    "tamperedTenants": [
      { "tenantId": "uuid", "slug": "pied-piper", "name": "Pied Piper",
        "tamperedRowCount": 2, "lastVerifiedAt": "..." }
    ],
    "totalVerifiedRows": 472355,
    "schedulerCron": "0 30 3 * * *",
    "schedulerNextRunAt": "2026-05-25T03:30:00Z",
    "adminPollingIntervalSec": 60,
    "lastVerifyP99Ms": 920,
    "lastVerifyAvgMs": 284,
    "perTenant": [
      { "tenantId": "uuid", "slug": "acme", "name": "Acme Corp",
        "status": "INTACT", "verifiedRows": 7411,
        "lastVerifiedAt": "2026-05-24T11:31:00Z", "tamperedRowCount": 0 }
    ]
  }
  ```

#### `POST /api/v1/admin/platform/audit-chain/verify`
- 모든 ACTIVE tenant를 직렬 verify, 결과 반환. 응답:
  ```json
  {
    "startedAt": "...", "completedAt": "...",
    "tenantsChecked": 9, "tenantsIntact": 8, "tenantsTampered": 1,
    "perTenant": [
      { "tenantId": "...", "intact": true, "verifiedRows": 7411, "durationMs": 142 }
    ],
    "errors": []
  }
  ```
- 일부 tenant verify가 실패해도 응답 200 + `errors[tenantId]`로 보고. 나머지 결과는 정상 포함.

### 3.3 메트릭 인프라

- **HTTP request latency p95/p99**: Spring Boot Actuator의 `http.server.requests` 타이머가 이미 Micrometer에 등록되어 있다. activity-summary controller가 `MeterRegistry.find("http.server.requests").timer()`에서 직접 snapshot을 읽어 응답에 채운다. Prometheus endpoint 외부 노출 불필요.
- **Audit chain verify latency p99**: 신규 `Micrometer.Timer audit.chain.verify` (tag: `tenantId`)를 `AuditChainService.verify` 진입/종료에 부착. status endpoint가 이 타이머의 snapshot을 읽음.
- JVM 시작 후 트래픽이 없어 카운터가 0이면 응답의 `latency`는 0이 아닌 `null` — 클라이언트는 `—`로 표시.

### 3.4 검증 주기 라벨 — A안 채택

mockup의 `검증 주기 60s`는 의미를 두 가지로 해석할 수 있다.
- (A) **어드민 새로고침 주기 60s** + scheduler는 기존대로 매일 03:30 UTC 1회
- (B) scheduler를 60초로 단축

**A 채택**. 60초마다 모든 tenant verify는 audit_log가 수십만 rows에 도달했을 때 DB 부담이 크고 `scheduler_lease` leader 경합도 증가한다. mockup이 주려는 "실시간 모니터링감"은 어드민의 60초 polling으로 충분히 달성된다.

메트릭 카드의 subline은 `"매일 03:30 UTC · 어드민 새로고침 60s"`로 명확화.

## 4. 서버 구현

### 4.1 신규 메서드 — `AuditEventType.category()`

```java
public enum AuditEventType {
  // ...
  CREDENTIAL_AUTHENTICATED(Category.CEREMONY),
  SIGNATURE_COUNTER_REGRESSION(Category.SECURITY_FAIL),
  API_KEY_ISSUED(Category.ADMIN_ACTION),
  // ...

  public enum Category { CEREMONY, ADMIN_ACTION, SECURITY_FAIL }
  public Category category() { return this.category; }
}
```

분류 매핑:
- `ceremony`: REGISTRATION_OPTIONS_REQUESTED, CREDENTIAL_REGISTERED, AUTHENTICATION_OPTIONS_REQUESTED, CREDENTIAL_AUTHENTICATED, CREDENTIAL_BACKUP_STATE_CHANGED
- `admin-action`: TENANT_CREATED, TENANT_SUSPENDED, TENANT_ACTIVATED, API_KEY_ISSUED, API_KEY_REVOKED, WEBAUTHN_CONFIG_UPDATED, ADMIN_USER_CREATED, ADMIN_USER_DELETED, ADMIN_USER_PASSWORD_RESET, CREDENTIAL_REASSIGNED, CREDENTIAL_RENAMED, USER_FORCE_LOGOUT, REFRESH_TOKEN_REVOKED
- `security-fail`: SIGNATURE_COUNTER_REGRESSION, CREDENTIAL_AUTH_RATE_LIMIT, ATTESTATION_TRUST_FAILED, CREDENTIAL_AUTO_SUSPENDED, CREDENTIAL_REVOKED, CREDENTIAL_UNSUSPENDED (역방향이지만 security event 흐름의 일부)

서버는 응답의 `category` 필드를 미리 채워서 보낸다. 클라이언트는 분류 로직 없음 — single source of truth는 서버 enum.

### 4.2 신규 서비스 — `PlatformAuditChainService`

- `status()`: 모든 ACTIVE tenant 순회. tenant별 마지막 verify 결과를 Caffeine 캐시(TTL 60s)에서 읽음. 캐시 miss면 즉시 verify.
- `verifyAll()`: 모든 ACTIVE tenant를 **직렬** verify, 동기 200 OK 응답. 전체 timeout 60초 (controller 단에서 `@Async` 없이 처리, 9 tenant × 평균 920ms 기준 ~8초 예상). tenant 수가 늘어 60초 초과 위험이 보이면 별도 spec으로 비동기(202 Accepted + status polling) 전환. 병렬은 P0에서 지양 (DB 부담 + scheduler_lease 경합).
- 모든 메서드는 `APP_ADMIN` DataSource(EXEMPT ACCESS POLICY) 위에서 동작 → VPD 우회. 기존 platform-stats 패턴 동일.

### 4.3 신규 서비스 — `PlatformActivityService`

- `summary(window)`: AuditLogRepository에 신규 메서드 `countByCreatedAtAfter(since)` / `countByCategoryAndCreatedAtAfter(category, since)` / cross-tenant 호출. tenant별 24h 이벤트 수는 GROUP BY로 한 번에. Top-5는 ORDER BY count DESC LIMIT 5.
- `feed(cursor, category, tenantIds)`: AuditLogRepository에 신규 `findCrossTenantPaged(cursor, category, tenantIds, limit)`. cursor는 `(createdAt, id)` 복합 키로 안정적 페이지네이션.

### 4.4 신규 controller 2개

- `AdminPlatformActivityController` — `/api/v1/admin/platform/activity-summary`, `/api/v1/admin/platform/activity-feed`
- `AdminPlatformAuditChainController` — `/api/v1/admin/platform/audit-chain/status`, `/api/v1/admin/platform/audit-chain/verify`

두 controller 모두 `AdminAuthz.requirePlatformOperator()` 한 줄로 시작. ArchUnit Rule 5/6에 이미 `/api/v1/admin/**` prefix는 포함되어 있어 추가 규칙 변경 불필요.

## 5. Admin SPA 구현

### 5.1 신규 라우트 + 라우트 가드

- `App.tsx` (또는 `routes/*`)에 두 라우트 추가.
- `RequirePlatformOperator` 가드 (이미 `/tenants`, `/admins`, `/system`에서 사용 중인 패턴) 재사용.
- 사이드바 `Sidebar.tsx`에서 mock URL을 실제 라우트로 교체. RP_ADMIN role에서는 두 항목 hide.

### 5.2 Activity 페이지 컴포넌트 트리

```
ActivityPage.tsx
├── ActivityHeader (제목, 새로고침, 내보내기)
├── ActivityMetricsRow (MetricCard × 4)
├── 2-column layout
│   ├── ActivityFeedPanel
│   │   ├── FeedFilterTabs (전체 / 운영 액션 / 보안 실패)
│   │   ├── FeedTenantFilter (선택된 tenant chips)
│   │   └── FeedList (cursor pagination, 30개씩)
│   │       └── FeedRow × N
│   └── ActiveTenantsPanel
│       └── TenantRankRow × 5
└── TenantFilterChips (전체 tenant chip, 다중 선택)
```

데이터 흐름:
- `useActivitySummary()` — `useQuery key=["platform","activity-summary","24h"]`, staleTime 30s, refetchInterval 30s.
- `useActivityFeed(category, tenantIds)` — `useInfiniteQuery key=["platform","activity-feed",category,tenantIds]`, staleTime 10s, refetchInterval 10s.

### 5.3 Audit Chain Monitor 페이지 컴포넌트 트리

```
AuditChainMonitorPage.tsx
├── PageHeader (제목 + [월간 보고서] [전체 즉시 검증])
├── ChainMetricsRow (MetricCard × 4)
├── TamperedAlertBanner (조건부)
└── ChainStatusTable
    └── TenantChainRow × N
        └── 행 액션: [열기] [검증]
```

데이터 흐름:
- `useAuditChainStatus()` — `useQuery key=["platform","audit-chain","status"]`, staleTime 30s, refetchInterval 60s.
- `[행: 검증]` — 기존 `GET /api/v1/admin/tenants/{tenantId}/audit-logs/verify` 재사용 (단일 tenant), 완료 시 status query invalidate.
- `[전체 즉시 검증]` — 신규 POST verify-all, 완료 시 status invalidate.

### 5.4 사이드바 pill 데이터 소스 갱신

`Sidebar.tsx` 하단의 `AUDIT CHAIN OK · 마지막 검증 N분 전 · M행` pill은 현재 placeholder (정적 텍스트 또는 mock 데이터). Phase B에서 다음을 적용:

1. 기존 pill 구현 위치 식별 (`Sidebar.tsx` 또는 `BottomStatusPill.tsx` 류)
2. `useAuditChainStatus()` 훅으로 교체. status 응답의 `intactTenants === totalTenants`이면 초록 "AUDIT CHAIN OK", 아니면 빨강 "AUDIT CHAIN ALERT". `totalVerifiedRows`로 행 수, `perTenant`의 가장 최근 `lastVerifiedAt`으로 상대시간 표시.
3. 두 페이지(`/platform/activity`, `/platform/audit-chain`)와 query key를 공유하므로 캐시 재사용 — 추가 네트워크 호출 없음.

### 5.5 CSV export

`lib/csv.ts` 신규 헬퍼.
- Activity: 현재 필터 적용된 feed를 page-by-page로 **최대 5,000건**까지 페치 → CSV. 5,000건 초과 시 모달로 "기간을 좁히세요" 안내.
- Audit Chain: `audit-chain/status` 응답 + tenant별 lastVerifiedAt을 CSV 1장으로. 시간 추이는 본 spec 비대상.

### 5.6 "Incident 생성" placeholder

배너의 `[Incident 생성]` 버튼은 `alert("외부 ticket 시스템 연동 예정")` 또는 토스트로 안내만. 실제 통합은 별도 spec.

## 6. 에러 / 빈 상태

| 상황 | UX |
|---|---|
| summary 로딩 실패 | 4개 카드 skeleton + "메트릭을 불러올 수 없습니다 — 재시도" 토스트 |
| feed 빈 결과 | EmptyState ("선택한 필터에 맞는 이벤트가 없습니다") |
| feed 다음 페이지 실패 | 마지막 페이지 유지 + 인라인 "재시도" 버튼 |
| chain status 캐시 stale > 5분 | 메트릭 카드 우상단 ⚠ 인디케이터 |
| verifyAll 중 일부 실패 | 성공 결과 반영 + 실패 tenant 토스트 묶음 |
| tenant 0개 환경 | 메트릭 0/0/0 + 테이블 EmptyState |
| latency 메트릭 not-ready | 응답의 `latency = null` → `—` 표시 |

## 7. 테스트 전략

### 서버
| 레벨 | 대상 |
|---|---|
| Unit | `PlatformAuditChainService` — 일부 tenant verify 실패 시 결과 결합, 캐시 hit/miss 분기 |
| Unit | `AuditEventType.category()` — 모든 enum 값이 세 카테고리 중 하나로 매핑 (exhaustive switch) |
| Slice (`@WebMvcTest`) | 신규 controller 2개 — Authz 게이트, DTO shape, paging param 검증 |
| Integration | `PlatformActivityIntegrationTest` — 4 tenant seed → cross-tenant 합산 정확 + RP_ADMIN으로 호출 시 403 + PLATFORM_OPERATOR로 호출 시 다른 tenant 데이터 보임 (positive VPD bypass) |
| Integration | `PlatformAuditChainIntegrationTest` — 한 tenant audit row hash 인위 손상 → `tamperedTenants`에 등장, intact한 다른 tenant 영향 없음 |

### Admin SPA
| 레벨 | 대상 |
|---|---|
| Vitest unit | helper (formatRelativeTime, etc.), hook query key 정합 |
| Vitest component | `ActivityFeedPanel` — empty/loading/error/pagination 4상태. `TamperedAlertBanner` — `length===0` 시 unmount |
| Playwright e2e | Platform Operator 로그인 → Activity 페이지 메트릭 + 피드 + 필터. Audit Chain 페이지 tampered seed에서 배너 + "tenant 열기" 클릭 시 audit-logs 이동 |
| Playwright e2e | RP_ADMIN 로그인 시 사이드바에 두 항목 미노출 + URL 직접 입력해도 차단 |

## 8. 롤아웃

### Phase A — 서버 (PR #1)
1. `AuditEventType.Category` enum + `category()` 메서드 + unit test
2. `Micrometer.Timer audit.chain.verify` 부착
3. `PlatformAuditChainService` (status, verifyAll, Caffeine 캐시)
4. `PlatformActivityService` (summary, feed)
5. `AdminPlatformActivityController` + `AdminPlatformAuditChainController`
6. slice tests × 2 + integration tests × 2
7. spotless + ArchUnit + `./gradlew check` 통과

### Phase B — 어드민 (PR #2, A 머지 후)
1. 타입 (`PlatformActivitySummary`, `PlatformActivityFeedItem`, `AuditChainStatus`, ...)
2. `MetricCard` 재사용 (OverviewTab의 것을 공통화 — 이미 분리되어 있으면 그대로 사용)
3. `ActivityPage` + 7개 sub-component
4. `AuditChainMonitorPage` + 6개 sub-component
5. 사이드바 mock URL → 실제 라우트, RP_ADMIN role hide
6. `lib/csv.ts` 클라이언트 export 헬퍼
7. 사이드바 pill을 `useAuditChainStatus`로 wire-up
8. Playwright e2e × 2

## 9. 위험 / 미해결

| 항목 | 처리 |
|---|---|
| HTTP latency 메트릭이 워밍업 전엔 null | 응답 `latency=null` + 클라 `—` 표시 |
| scheduler_lease 노출 안 함 | p99는 Micrometer 타이머로 충분, scheduler leader 정보 비대상 |
| VPD 우회 권한 검증 | 통합 테스트의 positive case에서 적극 검증 (RP_ADMIN 403만이 아니라 PLATFORM_OPERATOR가 cross-tenant 정말 보이는지) |
| CSV export 부하 | 5,000건 클라 가드. 서버 rate limit 안 둠 (어드민 사용자군 작음) |
| 피드 폴링 10s가 audit_log에 부담 | 인덱스 점검 필요 — `audit_log(created_at DESC, id DESC)` 복합 인덱스 존재 여부 확인. 없으면 Phase A에 마이그레이션 추가 |

## 10. 향후 (별도 spec)

- Incident 생성 외부 ticket (PagerDuty / Slack / Jira) 통합
- PDF 보고서 생성 파이프라인
- WebSocket / SSE 실시간 푸시
- ⌘K 글로벌 검색
- Mini chart sparkline (tenant별 시간대별 verify rate)
- 시간대별 chain length 누적 차트
- 운영자 자신의 활동 로그 화면 (admin self-audit)
