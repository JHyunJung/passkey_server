# Cross-Tenant 플랫폼 통계 — 설계 문서

> 작성일: 2026-05-21 · 상태: 설계 승인 대기

## 1. 배경 / 문제

Admin 콘솔 `/tenants` 페이지(`admin/src/pages/TenantsListPage.tsx`) 상단에는 4개의
MetricCard가 있다. 그중 "활성 Tenant"만 실데이터를 반영하고, 나머지 3개 — "등록
Credential", "유효 API Key", "24h ceremony" — 는 하드코딩된 `"—"` placeholder다.
코드 주석이 그 사실을 명시한다: *"visual scaffolding from the handoff design until
backend stats land"*.

이 3개는 **전체 테넌트를 가로지르는 합산(cross-tenant aggregate) 지표**다. 현재
백엔드에는 단일 테넌트 단위 통계 API(`GET /api/v1/admin/tenants/{id}/overview-stats`)만
있어, 프론트가 호출할 cross-tenant 엔드포인트가 없다.

**의도하는 결과**: Platform Operator가 `/tenants` 페이지에서 플랫폼 전체의 활성
Credential 수, 활성 API Key 수, 최근 24시간 ceremony 시작 건수를 한눈에 본다.

## 2. 핵심 제약 — 왜 단순하지 않은가

멀티테넌트 격리가 Oracle VPD(Virtual Private Database)로 구현되어 있다.
`TenantContextHolder.set(tenantId)`를 호출하는 순간부터 그 세션의 모든 SQL에
`WHERE tenant_id = HEXTORAW(SYS_CONTEXT(...))` predicate가 자동 부착된다. 즉 **단일
테넌트로 고정**되며, 한 쿼리로 여러 테넌트를 합산할 수 없다.

cross-tenant 조회의 유일한 안전 경로는 `APP_ADMIN` 데이터소스다. 이 DB 유저는
`EXEMPT ACCESS POLICY` 권한을 가져 VPD predicate가 적용되지 않으며, `credential` /
`api_key` / `audit_log`에 `SELECT` 권한이 있다.

기존 선례: `ApiKeyAdminWriter`(`auth/apikey/repository/`)가 이미 같은 패턴을 쓴다 —
`NamedParameterJdbcTemplate adminJdbcTemplate` 주입 + `@Transactional("adminTransactionManager")`.
이번 작업은 이 패턴을 그대로 따른다.

## 3. 아키텍처

```
[TenantsListPage]  useQuery(staleTime 60s)
       │  GET /api/v1/admin/platform/stats
       ▼
[AdminPlatformStatsController]  @ConditionalOnProperty(admin.enabled=true)
       │  AdminAuthz.requirePlatformOperator()   ← TenantContextHolder 설정 안 함
       ▼
[AdminPlatformStatsService]  @ConditionalOnProperty(admin.enabled=true)
       │  @Transactional("adminTransactionManager")
       ▼
[adminJdbcTemplate]  → APP_ADMIN 데이터소스 (VPD 우회)
       │  native SQL × 3
       ▼
  credential / api_key / audit_log  (전체 테넌트 row)
```

`passkey.admin.enabled=false`(RP-only 배포)에서는 `adminJdbcTemplate` 빈 자체가
없으므로, 서비스·컨트롤러도 동일한 `@ConditionalOnProperty`로 부재해야 한다.
그렇지 않으면 RP-only 배포의 ApplicationContext 기동이 실패한다.

## 4. 구성요소

### 4.1 백엔드 — 집계 서비스 (신규)

`server/src/main/java/com/crosscert/passkey/admin/service/AdminPlatformStatsService.java`

- `@Component` + `@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")`
- 생성자 주입: `NamedParameterJdbcTemplate adminJdbcTemplate` (필드명 `adminJdbc`)
- 메서드: `@Transactional("adminTransactionManager") public PlatformStats compute()`
  (readOnly)

반환 record (서비스와 같은 파일 또는 별도 파일):

```java
public record PlatformStats(long activeCredentials, long activeApiKeys, long ceremonies24h) {}
```

native SQL 3건 — 각각 `adminJdbc.queryForObject(sql, params, Long.class)`:

```sql
-- 1. ACTIVE credential 총합
SELECT count(*) FROM credential WHERE status = :status

-- 2. ACTIVE api_key 총합
SELECT count(*) FROM api_key WHERE status = :status

-- 3. 최근 24h ceremony 시작 건수
SELECT count(*) FROM audit_log
 WHERE event_type IN (:eventTypes)
   AND created_at >= :fromTs
```

**enum → 파라미터 바인딩 (SQL 리터럴 금지)**:
- `:status` ← `CredentialStatus.ACTIVE.name()` / `ApiKeyStatus.ACTIVE.name()`
- `:eventTypes` ← `List.of(AuditEventType.REGISTRATION_OPTIONS_REQUESTED.name(),
  AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED.name())`
- `:fromTs` ← `OffsetDateTime.now(ZoneOffset.UTC).minusHours(24)`
  (`audit_log.created_at`에 `OffsetDateTime` 바인딩 — `AuditAggregationService`가
  이미 검증한 패턴)

enum 이름이 바뀌면 컴파일 시점에 드러나고, 오타·SQL injection 여지가 없다.

### 4.2 백엔드 — 엔드포인트 (신규)

`server/src/main/java/com/crosscert/passkey/admin/controller/AdminPlatformStatsController.java`

```java
@RestController
@RequestMapping("/api/v1/admin/platform")
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
@RequiredArgsConstructor
@Tag(name = "Admin · Platform", description = "Cross-tenant aggregate stats. PLATFORM_OPERATOR only.")
public class AdminPlatformStatsController {

  private final AdminPlatformStatsService statsService;

  public record PlatformStatsView(long activeCredentials, long activeApiKeys, long ceremonies24h) {}

  @GetMapping("/stats")
  public ApiResponse<PlatformStatsView> stats() {
    AdminAuthz.requirePlatformOperator();
    PlatformStats s = statsService.compute();
    return ApiResponse.ok(
        new PlatformStatsView(s.activeCredentials(), s.activeApiKeys(), s.ceremonies24h()));
  }
}
```

- 경로: `GET /api/v1/admin/platform/stats` — ArchUnit Rule 5(`/api/v1/admin` prefix) 통과
- `requirePlatformOperator()` — PLATFORM_OPERATOR 전용. `TenantContextHolder`를
  설정하지 않음(cross-tenant 조회이므로 의도된 동작). RP_ADMIN은 `ADMIN_ROLE_FORBIDDEN`
- `ApiResponse<T>` envelope 통일
- 별도 컨트롤러로 둔 이유: `AdminSystemController`는 항상 활성 빈인데, 이 기능은
  `adminJdbcTemplate` 의존이라 conditional이어야 한다. 라이프사이클을 섞지 않는다.

### 4.3 프론트엔드

`admin/src/types/api.ts` — 타입 추가:

```ts
export interface PlatformStatsView {
  activeCredentials: number;
  activeApiKeys: number;
  ceremonies24h: number;
}
```

`admin/src/pages/TenantsListPage.tsx`:

```ts
const { data: stats, isLoading: statsLoading } = useQuery({
  queryKey: ["platformStats"],
  queryFn: () => apiGet<PlatformStatsView>("/api/v1/admin/platform/stats"),
  staleTime: 60_000,
});
```

3개 MetricCard 교체 (현재 `value="—"` 하드코딩 라인):

```tsx
<MetricCard label="등록 Credential"
  value={statsLoading ? "…" : fmtMaybe(stats?.activeCredentials)} sub="전체 ACTIVE" />
<MetricCard label="유효 API Key"
  value={statsLoading ? "…" : fmtMaybe(stats?.activeApiKeys)} sub="전체 ACTIVE" />
<MetricCard label="24h ceremony"
  value={statsLoading ? "…" : fmtMaybe(stats?.ceremonies24h)} sub="최근 24h 시작 건수" />
```

- `fmtMaybe`: 값 있으면 숫자 포맷, `undefined`/에러면 `"—"` — `OverviewTab.tsx`의
  기존 헬퍼와 동일 동작. `@/lib/format`에 공통 헬퍼가 있으면 재사용, 없으면 추출.
- 에러 처리: `useQuery` 에러 시 카드는 `"—"`. 통계는 보조 정보이고 페이지 핵심인
  tenants 목록과 무관하므로 별도 토스트 없음. 5xx는 `api.ts` 인터셉터가 Sentry로
  이미 보고.
- `staleTime`만 설정, `refetchInterval` 미설정 (서버 캐싱 없음, 프론트 60초 stale).

## 5. 데이터 흐름 / 캐싱

- 매 요청마다 서버가 native SQL 3건으로 실시간 COUNT. 서버 측 캐싱 없음.
- 프론트 TanStack Query `staleTime: 60_000` — 60초 내 재방문은 캐시 사용.
- 합산 통계는 변화가 느려(관리자 프로비저닝 직후에만 큰 변화) 60초 stale로 충분.

## 6. 에러 처리

- RP_ADMIN 호출 → `requirePlatformOperator()`가 `ADMIN_ROLE_FORBIDDEN` 던짐 → 403.
- `passkey.admin.enabled=false` 배포 → 컨트롤러 빈 부재 → 404 (admin 콘솔 자체가
  RP-only 배포엔 없으므로 호출자도 없음).
- 프론트 useQuery 에러 → 3개 카드 `"—"` 표시, 페이지 나머지는 정상.

## 7. 테스트

### 7.1 슬라이스 테스트 (DB 불필요)

`server/src/test/java/com/crosscert/passkey/slice/admin/AdminPlatformStatsControllerSliceTest.java`
— `AdminSystemControllerSliceTest` 패턴 복제:

- `@WebMvcTest(controllers = AdminPlatformStatsController.class, ...)`,
  `AdminPlatformStatsService`는 mock — `compute()`가 `new PlatformStats(10, 3, 42)` 반환
- 케이스:
  1. `stats_requires_platform_operator` — RP_ADMIN → 403, 에러 코드 검증
  2. `stats_returns_aggregate_for_platform_operator` — PLATFORM_OPERATOR → 200,
     `$.data.activeCredentials=10`, `activeApiKeys=3`, `ceremonies24h=42` 검증

### 7.2 통합 테스트 (실 Oracle, cross-tenant 합산 정확성)

native SQL + `APP_ADMIN` 데이터소스의 실제 동작은 통합 테스트로 검증한다.

- 현재 `application-test.yml`은 `passkey.admin.enabled=false` → `adminJdbcTemplate`
  부재. 신규 `application-admin-test.yml` 프로파일 추가: `passkey.admin.enabled=true`
  + `APP_ADMIN` 데이터소스 설정(`application-local.yml`의 `passkey.admin.datasource`
  블록 참고).
- 신규 통합 테스트: 서로 다른 2개 테넌트에 credential·api_key·audit_log row를
  시딩한 뒤, `AdminPlatformStatsService.compute()` 결과가 **양쪽 테넌트 합**과
  일치하는지 검증. ACTIVE 필터(REVOKED 제외), 24h 윈도우(25시간 전 이벤트 제외)도
  케이스로 포함.
- `IntegrationTestBase`의 시딩 헬퍼(`TenantSeed`) 재사용.

### 7.3 conditional 회귀 가드

`AdminDataSourceConditionTest`에 케이스 추가 — `passkey.admin.enabled=false`(test
프로파일)에서 `ctx.containsBean("adminPlatformStatsService") == false` 검증.

### 7.4 프론트엔드

`fmtMaybe`/`fmt` 헬퍼를 `@/lib/format`로 추출했다면 `admin/tests/unit/format.test.ts`에
케이스 추가(`fmtMaybe(undefined) === "—"`, `fmt(42)` 등). 컴포넌트 렌더 테스트
인프라는 기존에 사용 사례가 없어 이번 범위에서 제외.

## 8. ArchUnit / 코드 규칙 준수

| 규칙 | 준수 |
|------|------|
| Rule 1 (common→domain import 금지) | 신규 코드는 `admin`/`audit` 패키지 사용. `common`은 `ApiResponse`만 import(역방향). OK |
| Rule 5 (`@RequestMapping` prefix) | `/api/v1/admin/platform` → `/api/v1/admin` 시작. OK |
| 코드 규칙 1 (`@Transactional` 안 DB 접근) | `compute()`에 `@Transactional("adminTransactionManager")`. OK |
| 코드 규칙 6 (`ApiResponse<T>` envelope) | `ApiResponse.ok(...)`. OK |

새 테이블 추가가 아니므로 VPD policy / `RlsPolicyCatalogTest` 변경 불필요.

## 9. 작업 순서 (TDD, bite-sized)

1. `AdminPlatformStatsControllerSliceTest` 작성 — 컴파일 실패 (컨트롤러/서비스 미존재)
2. `PlatformStats` record + `AdminPlatformStatsService` — conditional, native SQL 3건, enum 바인딩
3. `AdminPlatformStatsController` — `/api/v1/admin/platform/stats`, conditional, `PlatformStatsView` → 슬라이스 테스트 통과
4. `AdminDataSourceConditionTest`에 빈 부재 케이스 추가
5. `application-admin-test.yml` + cross-tenant 합산 통합 테스트 (2 테넌트 시딩, ACTIVE 필터, 24h 윈도우)
6. `admin/src/types/api.ts`에 `PlatformStatsView` 추가
7. `TenantsListPage.tsx` — `useQuery`(staleTime 60s), 3개 MetricCard 연동, `fmtMaybe` 헬퍼
8. `./gradlew check` + `cd admin && npm run typecheck && npm run build && npm test`
9. `docs/architecture.md` §10 변경 이력에 `/api/v1/admin/platform` 엔드포인트 추가 기록

## 10. 검증 방법 (end-to-end)

1. 서버 기동(`--passkey.admin.enabled=true`) + Admin SPA 기동
2. `/tenants` 페이지 접속 → 상단 3개 카드가 `"—"`가 아닌 실제 수치 표시 확인
3. 패스키 등록/인증 수행 후 60초 경과 → 카드 수치 증가 확인
4. RP demo로 credential 추가 → "등록 Credential" 카드 반영 확인
5. `curl -b <admin-session> http://localhost:8080/api/v1/admin/platform/stats` →
   `{ activeCredentials, activeApiKeys, ceremonies24h }` 응답 확인
