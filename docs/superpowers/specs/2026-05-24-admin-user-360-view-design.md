# Admin 사용자 360° 뷰 — Design Spec

**일자**: 2026-05-24
**범위**: Admin 콘솔 (`admin/`) + Server (`server/`)
**테마**: RP 고객사 운영자가 우리에게 묻지 않고 자기 admin 콘솔에서 일을 끝낼 수 있게 — "이 사용자가 어떻게 됐나" 진단/조치 self-service.

## 1. 한 줄 요약

RP 고객사 운영자가 externalUserId로 사용자를 찾고, 해당 사용자의 credentials와 활성 세션을 한 화면에서 보고, 필요한 조치(개별 token revoke / 전체 logout / credential revoke / unsuspend)를 직접 수행할 수 있도록 사용자 목록 + 사용자 상세 (Credentials 탭 / Sessions 탭) 경로를 신설한다. AAGUID는 MDS BLOB에서 라벨로 자동 변환한다.

## 2. 배경 & 문제

현재 admin은 23개 엔드포인트를 노출하지만 "사용자 단위" 진입점이 없다. 자격증명은 `/tenants/{id}/credentials`에서 페이지네이션으로만 볼 수 있고, 특정 사용자의 자격증명+세션을 한꺼번에 확인할 방법이 없다. 운영 시 자주 들어오는 문의:

- "이 externalUserId로 등록된 사용자가 우리 테넌트에 있나?"
- "이 사용자가 어떤 인증기를 쓰고 있고 지금 몇 개 기기에서 로그인돼있나?"
- "이 사용자만 강제 로그아웃해주세요" (전체 logout-all은 이미 있지만 개별 세션 제어는 없음)

자격증명 카드의 AAGUID도 현재 raw UUID로만 표시되어 "이게 YubiKey인지 iCloud Keychain인지" 운영자가 구분 불가.

## 3. 비목표

- **Audit 검색 강화** — 본 테마 밖. eventType 서버사이드 필터는 다음 phase("히스토리/감사" 테마)에서 다룬다.
- **MDS 자동 suspend 이력 페이지** — 위와 같음. audit 검색이 강화되면 saved filter로 흡수될 예정이라 별도 페이지 만들지 않는다.
- **시계열 dashboard 위젯** — 별도 phase("추이 분석" 테마).
- **AAGUID 커뮤니티 lookup (passkey-aaguids)** — MDS BLOB만 사용. iCloud Keychain / Windows Hello 등 MDS 비등재 AAGUID는 "미등록" 배지로 표기. 후속 phase에서 확장 가능.
- **사용자 상세의 Activity 탭** — audit 그룹 작업 시 자연스럽게 추가될 hook만 비워둠.
- **기존 `CredentialView` DTO 변경** — backwards-compat 위해 신규 DTO로 분리.
- **DB 스키마 변경** — 없음.

## 4. 신규 Admin Endpoints

모두 `/api/v1/admin/tenants/{tenantId}/...` prefix, `@PreAuthorize` tenantAccess 권한 (기존 패턴 그대로).

| Method | Path | 설명 |
|--------|------|------|
| GET | `/users?q=&page=&size=` | 사용자 페이지 목록. `q`는 `externalUserId` substring(case-insensitive, 공백 trim). 정렬은 `created_at DESC` 고정. |
| GET | `/users/{tenantUserId}` | 사용자 메타 + 요약 카운트 (active/suspended/revoked credentials, active sessions) |
| GET | `/users/{tenantUserId}/credentials?page=&size=` | 해당 사용자의 credentials. AAGUID 라벨 포함. |
| GET | `/users/{tenantUserId}/refresh-tokens?status=active\|all&page=&size=` | 해당 사용자의 refresh token 목록. `status` 기본 `active`. |
| DELETE | `/users/{tenantUserId}/refresh-tokens/{tokenId}` | 개별 token revoke. 사유 `ADMIN_REVOKED`. |

**기존 endpoint 유지**:
- `POST /users/{tenantUserId}/logout-all` — Sessions 탭의 "모두 로그아웃" 버튼에서 그대로 호출
- `DELETE /tenants/{tenantId}/credentials/{credentialId}` + `/unsuspend` — Credentials 탭의 행 액션에서 그대로 호출

응답 envelope은 기존 `ApiResponse<T>` 규약, 에러 코드는 기존 `ErrorCode` enum을 따른다. 페이지네이션 응답 형식도 기존 admin 페이지 응답과 동일.

## 5. UI 흐름 (관리자 콘솔)

### 5.1 디자인 시스템 / 신규 컴포넌트 정책

- 기존 `admin/` 스택 그대로: **Vite + React 18 + TS + Tailwind + shadcn/ui (Radix) + TanStack Query + React Router v6 + React Hook Form + date-fns**. 신규 의존성 추가 없음.
- 페이지 레이아웃은 `TenantsListPage` / `TenantDetailPage` 패턴 답습.
- 재사용 컴포넌트: `PageHeader`, `MetricCard`, `EmptyState`, `Segmented`, `CopyButton`, `BrandMark`, 그리고 `components/ui/` shadcn 컴포넌트(Button, Dialog, AlertDialog, Tabs, Dropdown, Badge, Table, Pagination).
- 탭은 `@radix-ui/react-tabs` (이미 설치됨).
- AAGUID "미등록" 배지는 기존 status badge 변형으로 통일(별도 디자인 토큰 X).
- **신규 reusable 컴포넌트 1개만 도출**: `AaguidLabel` — `{ aaguid: UUID, label: string, fromMds: boolean }` props 받아 라벨 + (필요 시) 배지를 렌더. credential 목록, credential 검색 결과, 향후 audit detail에서 3+ 곳 재사용 예정이라 분리.

### 5.2 사이드바 메뉴 추가

기존 사이드바에 **"사용자"** 메뉴 추가. 권한은 `tenantAccess` (기존 menu 가드 패턴).

### 5.3 사용자 목록 화면 (`/tenants/{tenantId}/users`)

- 상단: `PageHeader` (제목 + 헬프 텍스트)
- 검색박스: `q` (debounced 300ms, externalUserId substring) — `q`가 비어있으면 전체 페이지네이션, 있으면 필터링
- 테이블 컬럼: External User ID / Display Name / Credentials (count badge: `N active / M suspended / K revoked`) / Active sessions / 등록일 / (행 클릭 → 상세)
- 빈 상태: `EmptyState` (검색 결과 없음 / 사용자 없음 두 메시지 분기)
- 페이지네이션 컨트롤 (기존 패턴)

### 5.4 사용자 상세 화면 (`/tenants/{tenantId}/users/{tenantUserId}`)

- 상단 메타 카드 (`MetricCard` 3개): External User ID + (CopyButton) / Display Name / 등록일
- 요약 배지 줄: Active credentials, Suspended, Revoked, Active sessions
- 하단 **탭** (Tabs):
  - **Credentials** (default): 페이지네이션 테이블
    - 컬럼: AAGUID (`AaguidLabel`), Status badge, Nickname, 마지막 사용, 등록일, 액션
    - 행 액션 (shadcn DropdownMenu): Nickname 수정 (status=ACTIVE) / Revoke (status=ACTIVE) / Unsuspend (status=SUSPENDED) — 기존 endpoint 재사용. 수동 SUSPEND 액션은 제공하지 않음 (SUSPEND는 MDS 자동 파이프라인 전용)
    - 빈 상태: `EmptyState` ("이 사용자에게는 등록된 자격증명이 없습니다")
  - **Sessions**: 페이지네이션 테이블
    - 상단 컨트롤: `Segmented` (`Active only` / `All`), "모두 로그아웃" 버튼 (AlertDialog 확인 → `POST logout-all`)
    - 컬럼: Issued at, Expires at, Last used (가능 시), Status (revoked_at 있으면 revoked badge + reason)
    - 행 액션: Revoke (AlertDialog 확인 → `DELETE /refresh-tokens/{id}`)
    - 빈 상태: `EmptyState` ("활성 세션이 없습니다")

탭 전환 시 URL query (`?tab=credentials|sessions`)에 반영하여 새로고침/공유 가능.

### 5.5 라우팅

- `/tenants/{tenantId}/users` — 목록
- `/tenants/{tenantId}/users/{tenantUserId}?tab=credentials|sessions` — 상세

기존 `TenantDetailPage`에서 사용자 메뉴로 진입 가능하도록 사이드바 + (옵션) 테넌트 상세 페이지 내 링크 추가.

## 6. 서버 사이드 설계

### 6.1 신규 도메인 컴포넌트

**`tenant.service.TenantUserQueryService`** (신규)
- `pageByTenant(q: String?, pageable: Pageable): Page<TenantUser>` — `TenantUserRepository`에 substring 쿼리 메서드 추가 (`@Query`로 `LOWER(external_id) LIKE LOWER(...)`)
- `requireById(tenantUserId: UUID): TenantUser` — 없으면 `TenantUserNotFoundException` (기존 ErrorCode 패턴, 신규 코드 `T###`)
- VPD를 통해 tenant 격리되므로 명시적 tenantId 인자 불필요 (`@Transactional` 안에서 동작)

**`auth.jwt.service.RefreshTokenAdminQueryService`** (신규)
- `pageByUser(tenantUserId: UUID, statusFilter: StatusFilter, pageable): Page<RefreshToken>` — `RefreshTokenRepository`에 메서드 추가
- `revokeOne(tokenId: UUID, actorAdminId: UUID): RevokeOutcome` — `RefreshTokenRepository`에 단건 revoke 메서드 추가, idempotent (`WHERE id=? AND revoked_at IS NULL`). 0행이면 이미 revoked 상태 — HTTP 200 + `{ alreadyRevoked: true }` 응답 (기존 `DELETE /credentials/{id}` 두 번 호출 시 동작과 일관). 존재 자체가 없으면 404. audit log는 실제 revoke된 케이스에만 기록.
- **VPD 경로(일반 `RefreshTokenRepository`) 사용**. Cross-tenant `RefreshTokenAdminWriter`(APP_ADMIN)는 이번 작업에서 건들지 않음 — MDS bulk revoke 전용 유지.

**`credential.service.AaguidLabelResolver`** (신규)
- 입력: `UUID aaguid` (nullable)
- 출력: `record AaguidLabel(UUID aaguid, String displayName, boolean fromMds)`
  - `aaguid == null` → `displayName = "unknown"`, `fromMds = false`
  - MDS 매치 → `displayName = metadataStatement.description`, `fromMds = true`
  - 매치 실패 → `displayName = aaguid.toString()`, `fromMds = false` → UI에서 "미등록" 배지
- 소스: `MdsBlobProvider.lastBlob.get()`의 `entries()`에서 `aaguid` lookup. blob 미적재 시 모두 `fromMds = false`
- 의존성: `MdsBlobProvider`. lookup 호출당 O(N) 순회를 피하기 위해 첫 호출 시 `Map<UUID, MetadataEntry>` 캐시 (blob refresh 이벤트(`MdsBlobRefreshedEvent`) 수신 시 invalidate)

### 6.2 신규 Controllers

**`admin.user.controller.TenantUserAdminController`** — endpoint 4개 (목록 / 상세 / credentials / refresh-tokens)
**`admin.user.controller.AdminRefreshTokenController`** — DELETE refresh-tokens/{id}

(controller 두 개로 쪼개는 이유: revoke는 mutating + audit 발생, 나머지는 read-only. 책임 명확.)

기존 ArchUnit Rule(`@RequestMapping` prefix 화이트리스트, RP controller의 repository 직접 호출 금지, common.* import 제한)에 위배되지 않도록 기존 admin controller 패턴 준수.

### 6.3 DTO

**서버 → 클라이언트 신규**:
- `TenantUserListItemView { id, externalUserId, displayName, credentialCount: { active, suspended, revoked }, activeSessionCount, createdAt }`
- `TenantUserDetailView { id, externalUserId, displayName, createdAt, credentials: { active, suspended, revoked }, sessions: { active, total } }`
- `UserCredentialItemView { id, credentialIdShort, aaguid: { value, label, fromMds }, status, suspendedReason?, nickname, createdAt, lastUsedAt }` — `credentialIdShort`는 raw credential_id의 첫 8 hex chars (UI 가독성, full id는 별도 모달/copy-to-clipboard에서)
- `RefreshTokenView { id, issuedAt, expiresAt, lastUsedAt?, revokedAt?, revokedReason? }`

count 집계는 단건 SQL `COUNT(*) ... GROUP BY status`로 list/detail 두 곳에서 동일 쿼리. N+1 회피.

### 6.4 권한 / 감사

- 신규 endpoint 5개 모두 `@PreAuthorize("@tenantAccess.canAccess(#tenantId)")` (기존 패턴)
- `DELETE refresh-tokens/{tokenId}` → audit log 1줄
  - `AuditEventType.REFRESH_TOKEN_REVOKED` (신규 enum 값) 또는 기존 `SESSION_REVOKED` 재사용 — 기존 enum 점검 후 결정 (단순 추가 가능 시 신규 값)
  - actor: `ADMIN`, subject: tenantUserId, payload: `{ tokenId, reason: "ADMIN_REVOKED" }`
- 조회성 endpoint 4개는 audit 안 함 (기존 컨벤션 — admin 목록/상세 조회는 audit하지 않음)

### 6.5 마이그레이션 / 호환성

- DB 스키마 변경 **없음**
- 기존 API 변경 **없음**
- 기존 DTO 변경 **없음** (신규 DTO만 추가)
- `MdsBlobRefreshedEvent` 새 listener(`AaguidLabelResolver`) 1개 추가 — 기존 `MdsRevocationScanListener`와 병행, 충돌 없음

## 7. 테스트 전략

### 7.1 서버

- **단위 테스트**
  - `TenantUserQueryServiceTest` — substring 매칭 (대소문자 무시, 공백 trim), 페이지네이션, 빈 결과
  - `RefreshTokenAdminQueryServiceTest` — status filter, idempotent revoke (이미 revoked 케이스)
  - `AaguidLabelResolverTest` — MDS 매치 / blob 없음 / aaguid null / blob refresh 시 캐시 invalidate
- **슬라이스 테스트** (Oracle 의존 — 기존 admin slice 베이스 사용)
  - `TenantUserAdminControllerSliceTest` — 4 endpoint × 권한 (allow / deny) × 페이지네이션 경계 × 검색 매칭
  - `AdminRefreshTokenControllerSliceTest` — DELETE 권한 / 본인 토큰 / 타 사용자 토큰 / 이미 revoked / 없는 ID
- **통합 테스트 (1개)**
  - `AdminUserViewIntegrationTest` — 시드 (2 tenant × 3 user × 다중 credential × 다중 token) → 사용자 목록 → 상세 → credentials 페이지 → refresh-tokens 페이지 → 개별 revoke → 다시 조회로 revoked 확인. cross-tenant 격리(다른 테넌트 사용자 ID로 GET → 404) 검증 포함.

### 7.2 클라이언트

- Vitest 단위:
  - `AaguidLabel` 컴포넌트 — MDS 라벨 / 미등록 배지 분기
  - 데이터 훅 (`useTenantUserList`, `useTenantUserDetail`, `useUserCredentials`, `useUserRefreshTokens`, `useRevokeRefreshToken`) — Mock fetch
- Playwright E2E:
  - 사용자 검색 → 행 클릭 → 상세 → 탭 전환 → 개별 revoke 확인 모달 → revoke 후 행이 revoked로 표시되는지 (또는 `Active only` 토글 끄면 보이는지) 한 시나리오
  - 권한 없는 사용자가 사용자 메뉴 접근 시 메뉴 미표시 검증

### 7.3 ArchUnit

기존 Rule 그대로 통과:
- 신규 controller가 `/api/v1/admin/**` prefix 안에 있음
- repository 직접 호출은 admin scope이라 허용(기존 RP만 금지)
- common.* import 금지 통과

## 8. Migration / Rollout

- **Phase 1 (1주차)**: 서버 — 도메인 + DTO + 5 endpoint + 테스트
- **Phase 2 (2주차)**: 클라이언트 — `AaguidLabel` + 데이터 훅 + 목록 화면 + 사용자 메뉴
- **Phase 3 (3주차)**: 클라이언트 — 상세 화면 (Credentials 탭 + Sessions 탭) + E2E
- **Phase 4 (4주차)**: 통합 / 폴리싱 / 운영자 onboarding 문서 갱신 (`admin/README.md`, `docs/operations.md` 해당 절)

Feature flag는 도입하지 않음 — 신규 endpoint이고 기존 동작에 영향 없음.

## 9. 위험 / 안전장치

| 위험 | 대비 |
|------|------|
| 검색 쿼리가 큰 테이블에서 느림 | `tenant_user(external_id)` 인덱스가 이미 unique 인덱스로 존재(기존 마이그레이션) → `LIKE` 좌우 wildcard는 인덱스 불가. 페이지네이션 size 상한(100) + Oracle plan 확인 시 첫 phase 끝나면 정밀 측정. 필요 시 후속 phase에 functional index 또는 검색용 컬럼 추가. |
| AAGUID 캐시 stale | `MdsBlobRefreshedEvent` 수신 시 invalidate (이미 `ApplicationReadyEvent` 이후 발행되도록 직전 PR에서 fix됨) |
| 개별 token revoke 오작동(잘못된 사용자 token 잡힘) | endpoint path가 `/users/{tenantUserId}/refresh-tokens/{tokenId}` — service에서 `tokenId` 조회 시 `tenant_user_id` 일치 검증. 불일치 → 404. VPD가 추가 안전망. |
| Sessions 탭 페이지가 expired token으로 도배 | 기본 `status=active` 필터로 시작. `All` 토글에서만 expired 표시. |
| 신규 DTO와 기존 `CredentialView` 사이 정보 비대칭 | Diataxis "Reference" 문서에 두 응답의 의도 차이 명시 (전체 테넌트 page용 vs 사용자 scope용) |

## 10. Open Questions (구현 시작 전 해소)

1. `AuditEventType` enum에 `REFRESH_TOKEN_REVOKED` 신규 값 추가 vs `SESSION_REVOKED` 재사용 — 기존 enum 점검 후 결정
2. `RefreshToken` 엔티티에 `last_used_at` 컬럼이 실제 존재하는지 — 없으면 UI에서 해당 컬럼 표시 생략 (DTO에서 optional)
3. 사용자 상세에 들어가는 진입점 — 사이드바만 vs 테넌트 상세 페이지 카드에서도 — 2주차 시작 전 admin owner 확인
4. 기존 `DELETE /credentials/{id}` idempotent 동작 (이미 revoked 상태 두 번째 호출 시 HTTP 200 vs 4xx) 확인 → 신규 `DELETE refresh-tokens/{id}`도 동일 컨벤션 적용 (§6.1 revokeOne 응답 형식 일관성)
5. 신규 `ErrorCode` (예: `TENANT_USER_NOT_FOUND`)의 도메인 prefix + 다음 미사용 번호 — 기존 enum의 `T` prefix 시퀀스 확인

## 11. 변경 이력

- 2026-05-24: 최초 작성 (brainstorming v1)
