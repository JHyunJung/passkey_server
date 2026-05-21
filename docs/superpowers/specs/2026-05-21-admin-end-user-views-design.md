# Admin 콘솔 End-user(tenant_user) 조회 — 설계 문서

> 작성일: 2026-05-21 · 상태: 설계 승인 대기

## 1. 배경 / 문제

Admin 콘솔의 테넌트 상세 페이지에는 7개 탭(Overview, WebAuthn, AAGUID 정책,
API Keys, Credentials, Audit Logs, Funnel)이 있다. 그런데 **end-user
(`tenant_user`) 자체를 조회하는 화면이 없다.** 운영자가 "X라는 사용자"를
찾으려면 Credentials 탭에서 credential 목록을 `externalId`로 검색해 우회해야
한다 — credential이 없는 사용자는 아예 안 보이고, 한 사용자의 전체 passkey를
모아 보기도 불편하다.

`tenant_user`는 멀티테넌트 IAM 플랫폼의 1차 도메인인데, 관리 콘솔에서
**전용 화면이 없는 유일한 도메인**이다 (tenant·credential·api_key·admin_user·
audit는 모두 전용 화면 보유).

**의도하는 결과**: 운영자가 한 테넌트의 end-user를 직접 목록·검색하고, 개별
사용자의 passkey 목록과 활동 이력을 한 화면에서 조회한다.

## 2. 범위

- **포함**: end-user 목록(검색·페이징), end-user 상세(passkey 목록 + 최근 활동).
- **조회 전용**: 강제 로그아웃·passkey 폐기 등 쓰기 액션은 추가하지 않는다.
  그 액션들은 이미 존재한다 (`AdminUserSessionController`의 logout-all API,
  Credentials 탭의 revoke).
- **권한**: `AdminAuthz.requireTenantAccess(tenantId)` — PLATFORM_OPERATOR와
  해당 테넌트의 RP_ADMIN 모두 접근.

## 3. 아키텍처

```
[TenantDetailPage] "Users" 탭
       │
       ├── UsersTab          GET /api/v1/admin/tenants/{tid}/users?q&page&size
       │      행 클릭 → navigate
       └── UserDetailPage    GET /api/v1/admin/tenants/{tid}/users/{userId}
              │ (별도 라우트 users/:tenantUserId)
              ▼
       [AdminEndUserController]  requireTenantAccess(tid)
              ├── TenantUserRepository.findByTenantIdWithSearch  (목록, 집계 조인)
              ├── TenantUserRepository.findById                  (상세)
              ├── CredentialRepository.findAllByTenantUserId      (상세의 passkey)
              └── AuditAggregationService.lastEventForSubject     (상세의 최근 활동)
```

## 4. 백엔드

### 4.1 Repository — `TenantUserRepository` 수정

현재 `findByExternalId`, `countByTenantId`만 있다. 추가:

**목록 + 검색 + 활성 passkey 개수 (페이징)** — N+1을 피하기 위해 `Credential`
`LEFT JOIN` + `GROUP BY`로 한 쿼리에 집계. projection interface로 반환:

```java
interface EndUserRow {
  UUID getId();
  String getExternalId();
  String getDisplayName();
  long getActiveCredentialCount();
  OffsetDateTime getCreatedAt();
  OffsetDateTime getUpdatedAt();
}

@Query(value =
  "SELECT u.id AS id, u.externalId AS externalId, u.displayName AS displayName, "
  + "u.createdAt AS createdAt, u.updatedAt AS updatedAt, COUNT(c.id) AS activeCredentialCount "
  + "FROM TenantUser u "
  + "LEFT JOIN com.crosscert.passkey.credential.domain.Credential c "
  + "  ON c.tenantUserId = u.id "
  + "  AND c.status = com.crosscert.passkey.credential.domain.CredentialStatus.ACTIVE "
  + "WHERE u.tenantId = :tenantId "
  + "  AND (:q IS NULL "
  + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
  + "       OR LOWER(COALESCE(u.displayName, '')) LIKE LOWER(CONCAT('%', :q, '%'))) "
  + "GROUP BY u.id, u.externalId, u.displayName, u.createdAt, u.updatedAt",
  countQuery =
  "SELECT COUNT(u) FROM TenantUser u WHERE u.tenantId = :tenantId "
  + "  AND (:q IS NULL "
  + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
  + "       OR LOWER(COALESCE(u.displayName, '')) LIKE LOWER(CONCAT('%', :q, '%')))")
Page<EndUserRow> findByTenantIdWithSearch(
    @Param("tenantId") UUID tenantId, @Param("q") String q, Pageable pageable);
```

주의:
- **`countQuery` 필수** — `GROUP BY`가 있는 쿼리는 Spring Data가 count를 올바로
  추론하지 못한다. 명시하지 않으면 잘못된 단일 row count가 나온다.
- 정렬은 `GROUP BY`에 포함된 컬럼만 가능 → 컨트롤러에서 `createdAt` DESC 고정.
- `q IS NULL` 분기를 쿼리 안에 흡수 — 검색어 유무로 별도 메서드를 두지 않는다
  (`CredentialRepository.findByTenantIdWithSearch`와 동일한 검증된 패턴).
- LIKE는 양변 `LOWER(...)` — Oracle 대소문자 무시 검색.

상세는 JpaRepository 기본 `findById`를 쓰고, 경로 테넌트 소속은 컨트롤러에서
`getTenantId().equals(tenantId)`로 검증한다 (`AdminUserSessionController`와 동일
패턴 — 코드베이스 톤 일관).

### 4.2 Service — `AuditAggregationService` 메서드 1개 추가

상세의 "최근 활동 시각"을 위해 `lastEventForSubject(UUID tenantId, String
subjectId)` 추가 — 기존 `lastEventAt`을 복제해 `AND subject_id = :sid` 추가.
audit_log는 `subject_id = tenantUserId.toString()`로 느슨하게 연결된다.
`subject_id`에 인덱스가 없을 수 있으나 상세 1건당 1회 부분 스캔이라 허용 범위
(목록에는 넣지 않는다 — 행마다 audit MAX는 무겁다).

### 4.3 Controller — `AdminEndUserController` 신규

`@RestController @RequestMapping("/api/v1/admin/tenants/{tenantId}/users")`.

`AdminUserSessionController`가 같은 base path에 `POST /{tenantUserId}/logout-all`을
이미 점유하지만, HTTP 메서드와 하위 경로가 달라 충돌하지 않는다 (Spring MVC는
path+method 조합으로 핸들러를 구분). 별도 컨트롤러로 둔다 — `AdminUserSession
Controller`는 "force-logout / incident response"로 책임이 좁고, 조회 기능은
의존성(`CredentialRepository`, `AuditAggregationService`)도 다르다. 같은 base
path를 두 컨트롤러가 나눠 쓰는 선례가 이미 있다 (`AdminTenantOverviewController`
+ `AdminCredentialController`).

엔드포인트:
- `GET /` — 목록. `requireTenantAccess` → `findByTenantIdWithSearch` →
  `PageResponse<EndUserView>`. 파라미터 `q`(검색, blank→null), `page`, `size`.
- `GET /{tenantUserId}` — 상세. `requireTenantAccess` → `findById` + 테넌트 소속
  검증 → credential 목록 + 최근 활동 → `EndUserDetailView`.

둘 다 `@Transactional(readOnly = true)` (VPD 컨텍스트는 `requireTenantAccess`가
설정, DB 접근은 트랜잭션 안에서).

### 4.4 응답 DTO (컨트롤러 inner record)

```java
record EndUserView(
    UUID id, String externalId, String displayName,
    long activeCredentialCount, OffsetDateTime createdAt, OffsetDateTime updatedAt) {}

record EndUserDetailView(
    UUID id, String externalId, String displayName,
    OffsetDateTime createdAt, OffsetDateTime updatedAt,
    long activeCredentialCount, OffsetDateTime lastActivityAt,
    List<CredentialView> credentials) {}
```

`CredentialView`(원래 RP-facing DTO)는 `AdminCredentialController`가 이미
재사용하는 선례가 있으므로 그대로 재사용한다 (중복 DTO 금지).

### 4.5 ErrorCode

신규 불필요. `ENTITY_NOT_FOUND`(상세 없음), `INVALID_INPUT`(cross-tenant 접근),
`ADMIN_ROLE_FORBIDDEN`(RP_ADMIN이 남의 테넌트) 모두 기존 enum 재사용.

## 5. 프론트엔드

### 5.1 타입 — `admin/src/types/api.ts`

```ts
export interface EndUserView {
  id: string;
  externalId: string;
  displayName: string | null;
  activeCredentialCount: number;
  createdAt: string;
  updatedAt: string;
}
export interface EndUserDetailView {
  id: string;
  externalId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
  activeCredentialCount: number;
  lastActivityAt: string | null;
  credentials: CredentialView[];
}
```

### 5.2 목록 — `UsersTab.tsx` 신규

`CredentialsTab.tsx`를 템플릿으로, 조회 전용으로 단순화 (rename/revoke/dropdown
제거). `useDebounced` 검색(300ms), `page`/`size=50`, TanStack `useQuery`
(`["endUsers", tenantId, {page,size,q}]`) → `apiGet<PageResponse<EndUserView>>`.
테이블 컬럼: External ID, Display Name, Active Passkeys, Created, Updated.
행 클릭 → `users/{id}` 라우트로 이동. `EmptyState`/`PageHeader`/페이지네이션은
기존 컴포넌트 재사용. 포매팅은 `@/lib/format`(`formatDateTime`, `formatCount`,
`lastN`).

### 5.3 상세 — `UserDetailPage.tsx` 신규 (별도 라우트)

`useParams`로 `tenantId`/`tenantUserId`, `useQuery(["endUser", ...])` →
`apiGet<EndUserDetailView>`. 구성:
- 상단: PageHeader(externalId/displayName), "← 목록" 링크, 메타 카드(id,
  createdAt, updatedAt, activeCredentialCount, lastActivityAt)
- 하단: 이 유저의 credential 테이블 — CredentialsTab 테이블 마크업을 조회
  전용으로 축소
- 조회 전용 — mutation/Dialog 없음.

다른 탭들은 작은 액션 폼을 모달로 쓰지만, end-user 상세는 passkey 목록·메타·
활동 등 정보량이 많아 모달에 부적합하다. 별도 라우트는 URL 공유·뒤로가기도
지원한다.

### 5.4 라우팅 / 탭 등록

- `TenantDetailPage.tsx`의 `TABS` 배열에 `{ to: "users", label: "Users" }` 추가
  (`api-keys` 다음, `credentials` 앞 — "사용자 → 자격증명" 순서).
- `App.tsx`: `UsersTab`/`UserDetailPage` `lazy` import, `RequireTenantAccess`
  블록 안에 `<Route path="users" .../>`, `<Route path="users/:tenantUserId" .../>`.
- `TenantDetailPage`의 탭 `NavLink`는 `end` prop이 없어 prefix 매칭이므로,
  `users/:id` 상세에서도 "Users" 탭이 active 유지된다 (추가 작업 불필요).

## 6. 데이터 흐름 / 에러 처리

- 목록·상세 모두 `useQuery` — 기본 캐싱. 검색은 debounce 후 queryKey 변경으로
  재요청.
- 상세에서 없는 `tenantUserId` → 백엔드 404(`C003`) → 프론트에서 "사용자를
  찾을 수 없음" 표시.
- cross-tenant 접근 → 백엔드 400(`C001`); RP_ADMIN이 남의 테넌트 → 403(`M002`,
  `requireTenantAccess`).

## 7. 테스트

### 7.1 슬라이스 — `AdminEndUserControllerSliceTest` 신규

`AdminUserSessionControllerSliceTest`를 템플릿으로. `@WebMvcTest`, repository와
`AuditAggregationService`는 mock. 케이스:
1. `list_returns_paged_users` — PLATFORM_OPERATOR, mock `Page<EndUserRow>` →
   `$.data.content[0].activeCredentialCount` 검증
2. `list_passes_search_q_to_repo` — `q` 파라미터가 repo 호출 인자로 전달되는지 verify
3. `detail_returns_user_with_credentials` — credential 목록 + `lastActivityAt` shape
4. `detail_rejects_cross_tenant_user` — 다른 테넌트 유저 → 400 `C001`
5. `detail_returns_404_when_user_missing` → 404 `C003`
6. `rp_admin_forbidden_on_other_tenant` — RP_ADMIN 남의 테넌트 → 403 `M002`

### 7.2 통합 — `AdminEndUserIntegrationTest` 신규

검색·페이징·집계의 정확성은 실 Oracle에서만 검증 가능 (슬라이스는 mock이라
쿼리 자체를 못 본다). 한 테넌트에 여러 end-user + 일부에 ACTIVE/REVOKED
credential을 시딩하고:
- 검색어가 externalId·displayName 양쪽에 매칭되는지
- `activeCredentialCount`가 ACTIVE만 세는지 (REVOKED 제외)
- 페이지 경계(page/size)와 `countQuery` 정합성
- cross-tenant 격리 (다른 테넌트 유저가 안 섞이는지)

기존 통합 테스트 인프라(`IntegrationTestBase`, `TenantSeed`) 재사용.

### 7.3 프론트

신규 format util을 만들지 않으므로 컴포넌트 테스트 추가 없음 (기존에 컴포넌트
렌더 테스트 인프라 미사용). `npm run typecheck` + `npm run build`로 정합성 검증.

## 8. ArchUnit / 코드 규칙 준수

| 규칙 | 준수 |
|------|------|
| Rule 5 (`@RequestMapping` prefix `/api/v1/admin`) | OK |
| Rule 6 (admin tenant controller가 `AdminAuthz` 의존) | `requireTenantAccess` 호출 — OK |
| Rule 3 (RP controller repository 직접 호출 금지) | admin controller는 예외 — OK |
| 코드 규칙 1 (`@Transactional` 안 DB 접근) | 두 핸들러 `@Transactional(readOnly=true)` — OK |
| 코드 규칙 6 (`ApiResponse<T>` envelope) | OK |

새 테이블 추가가 아니므로 VPD policy / `RlsPolicyCatalogTest` 변경 없음.

## 9. 작업 순서 (TDD, bite-sized)

1. `AdminEndUserController`의 DTO record 골격 + `EndUserRow` projection 정의
2. `AdminEndUserControllerSliceTest` 작성 — 컴파일/실행 실패(RED)
3. `TenantUserRepository`에 `findByTenantIdWithSearch` 추가
4. `AuditAggregationService.lastEventForSubject` 추가
5. `AdminEndUserController` 구현 → 슬라이스 테스트 통과(GREEN)
6. `AdminEndUserIntegrationTest` — 검색·집계·페이징·격리 검증
7. `admin/src/types/api.ts`에 `EndUserView`/`EndUserDetailView` 추가
8. `UsersTab.tsx`(목록) 작성
9. `UserDetailPage.tsx`(상세) 작성
10. `TenantDetailPage` TABS + `App.tsx` 라우팅 등록
11. `./gradlew check` + `cd admin && npm run typecheck && npm run build`
12. `docs/architecture.md` §10 변경 이력에 새 엔드포인트 2개 기록

## 10. 검증 (end-to-end)

1. 서버 + Admin SPA 기동, 테넌트 상세 진입
2. "Users" 탭 클릭 → end-user 목록 표시, 검색어 입력 시 externalId/displayName
   매칭, 페이지네이션 동작
3. 행 클릭 → `users/{id}` 상세 페이지, 메타·passkey 목록·최근 활동 표시
4. RP demo로 새 사용자 등록 후 → 목록에 반영, 상세에서 활성 passkey 수 증가
5. `curl -b <admin-session> .../tenants/{tid}/users` 및 `.../users/{userId}` →
   응답 shape 확인
6. RP_ADMIN 세션으로 다른 테넌트의 `/users` 호출 → 403
