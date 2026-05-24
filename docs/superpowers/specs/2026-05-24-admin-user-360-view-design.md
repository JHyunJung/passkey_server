# Admin 사용자 360° 뷰 — Design Spec

**일자**: 2026-05-24
**범위**: Admin 콘솔 (`admin/`) + Server (`server/`)
**테마**: RP 고객사 운영자가 우리에게 묻지 않고 자기 admin 콘솔에서 일을 끝낼 수 있게 — "이 사용자가 어떻게 됐나" 진단/조치 self-service.

## 1. 한 줄 요약

RP 고객사 운영자가 externalUserId로 사용자를 찾고, 해당 사용자의 credentials와 활성 세션을 한 화면에서 보고, 필요한 조치(개별 token revoke / 전체 logout / credential revoke / unsuspend)를 직접 수행할 수 있도록 사용자 목록 + 사용자 상세 (Credentials 탭 / Sessions 탭) 경로를 신설한다. AAGUID는 MDS BLOB에서 라벨로 자동 변환한다.

## 2. 배경 & 문제 (Brownfield)

현재 admin에 **사용자 진입점은 이미 부분적으로 있다** — `AdminEndUserController`(`/api/v1/admin/tenants/{id}/users` 목록 + 상세)와 `UsersTab.tsx` / `UserDetailPage.tsx` 화면이 read-only로 구현돼 있고, 전체 logout 액션(`AdminUserSessionController.forceLogout`)도 있다. 그러나 다음 갭이 운영 시 자주 마찰을 만든다:

1. **AAGUID가 raw UUID로만 표시** — 운영자가 "이 자격증명이 YubiKey인지 iCloud Keychain인지 Windows Hello인지" 구분 불가. MDS BLOB은 이미 메모리에 있고 `MetadataEntry.metadataStatement().description()`로 라벨을 얻을 수 있는데도 활용 안 함.
2. **사용자의 활성 세션을 볼 수 없음** — refresh token 목록 조회 endpoint도 UI도 없다. "이 사용자가 몇 개 기기에서 로그인돼있나"가 안 보인다. 전체 logout-all은 가능하나, 그 전에 "정말 다 끊어도 되는지" 확인할 단계가 없다.
3. **개별 세션 제어 불가** — 전체 logout-all은 너무 강한 도구라 "특정 기기만 끊기" 시나리오에서 RP가 우리에게 문의로 이관된다.
4. **Credentials 행 액션이 detail 화면에 없음** — 기존 `UserDetailPage`는 Passkeys 목록을 inline 표시만 한다. revoke/unsuspend/nickname 액션이 페이지 내에서 안 됨. (현재는 별도 `CredentialsTab`에서 가능)
5. **사용자 상세에 페이지네이션 없음** — `EndUserDetailView`가 credentials를 `List<CredentialView>`로 inline 포함한다. 사용자가 수십 개의 credential을 가진 경우 화면이 무거워진다.

## 3. 비목표

- **Audit 검색 강화** — 본 테마 밖. eventType 서버사이드 필터는 다음 phase("히스토리/감사" 테마)에서 다룬다.
- **MDS 자동 suspend 이력 페이지** — 위와 같음. audit 검색이 강화되면 saved filter로 흡수될 예정이라 별도 페이지 만들지 않는다.
- **시계열 dashboard 위젯** — 별도 phase("추이 분석" 테마).
- **AAGUID 커뮤니티 lookup (passkey-aaguids)** — MDS BLOB만 사용. iCloud Keychain / Windows Hello 등 MDS 비등재 AAGUID는 "미등록" 배지로 표기. 후속 phase에서 확장 가능.
- **사용자 상세의 Activity 탭** — audit 그룹 작업 시 자연스럽게 추가될 hook만 비워둠.
- **기존 `CredentialView` DTO 변경** — backwards-compat 위해 신규 DTO로 분리.
- **DB 스키마 변경** — 없음.

## 4. Admin Endpoints — 기존 + 신규

모두 `/api/v1/admin/tenants/{tenantId}/...` prefix. 권한은 `AdminAuthz.requireTenantAccess(tenantId)` 호출 (기존 컨벤션 — `@PreAuthorize` 대신 controller 내부에서 강제). 응답 envelope `ApiResponse<T>`, 페이지네이션은 `PageResponse<T>`.

### 4.1 기존 endpoint — 그대로 사용 (변경 없음)

| Method | Path | 비고 |
|--------|------|------|
| GET | `/users?q=&page=&size=` | `AdminEndUserController.list`. 검색은 externalId + displayName OR. 정렬 `createdAt DESC`. |
| POST | `/users/{tenantUserId}/logout-all` | `AdminUserSessionController.forceLogout`. 신규 Sessions 탭의 "모두 로그아웃" 버튼이 호출. |
| DELETE | `/tenants/{tenantId}/credentials/{credentialId}` | 기존 credential revoke. 신규 Credentials 탭 행 액션이 호출. |
| POST | `/tenants/{tenantId}/credentials/{credentialId}/unsuspend` | 기존 unsuspend. 신규 Credentials 탭 행 액션이 호출. |
| PATCH | `/tenants/{tenantId}/credentials/{credentialId}/nickname` | 기존 nickname 변경. 신규 Credentials 탭 행 액션이 호출. |

### 4.2 기존 endpoint — 변경

| Method | Path | 변경 내용 |
|--------|------|---------|
| GET | `/users/{tenantUserId}` | 응답 `EndUserDetailView`에서 `credentials: List<CredentialView>` 필드 **제거**. 대신 status별 카운트 `credentials: { active, suspended, revoked }` 객체로 대체 + `sessions: { active }` 추가. credentials는 4.3 신규 paged endpoint로 분리. **Breaking change** — 동시에 UI(`UserDetailPage`)도 함께 수정해 일관 유지. |

### 4.3 신규 endpoint

| Method | Path | 설명 |
|--------|------|------|
| GET | `/users/{tenantUserId}/credentials?page=&size=` | 해당 사용자의 credentials 페이지. 각 행에 AAGUID 라벨 객체 포함. |
| GET | `/users/{tenantUserId}/refresh-tokens?status=active\|all&page=&size=` | refresh token 페이지. `status` 기본 `active` (revoked_at IS NULL AND expires_at > now). `all`이면 expired/revoked까지. |
| DELETE | `/users/{tenantUserId}/refresh-tokens/{tokenId}` | 개별 token revoke. 사유 `RevokedReason.ADMIN_FORCED` (기존 enum 재사용 — 전체 logout과 동일 reason). 이미 revoked면 200 + `{ alreadyRevoked: true }`. tokenId가 path tenantUserId 소속 아니면 404. |

### 4.4 에러 코드

기존 `ErrorCode.ENTITY_NOT_FOUND` (C003) / `ErrorCode.INVALID_INPUT` (C001) / `ErrorCode.ADMIN_ROLE_FORBIDDEN` (M002) 재사용. **신규 코드 추가 없음.** (기존 `AdminEndUserController.detail`도 동일 패턴 사용 — 일관성)

## 5. UI 흐름 (관리자 콘솔) — Brownfield

### 5.1 디자인 시스템 / 신규 컴포넌트 정책

- 기존 `admin/` 스택 그대로: **Vite + React 18 + TS + Tailwind + shadcn/ui (Radix) + TanStack Query + React Router v6 + React Hook Form + date-fns**. 신규 의존성 추가 없음.
- 재사용 컴포넌트: `PageHeader`, `MetricCard`, `EmptyState`, `Segmented`, `CopyButton`, `BrandMark`, 그리고 `components/ui/` shadcn 컴포넌트(Button, Dialog, AlertDialog, Tabs, Dropdown, Badge, Table).
- 탭은 `@radix-ui/react-tabs` (이미 설치됨).
- AAGUID "미등록" 배지는 기존 status badge 변형으로 통일(별도 디자인 토큰 X).
- **신규 reusable 컴포넌트 1개만 도출**: `AaguidLabel` — `{ aaguid: string, label: string, fromMds: boolean }` props 받아 라벨 + (필요 시) 배지를 렌더. credential 목록, 향후 audit detail에서 재사용 예정이라 분리.

### 5.2 진입점 — 사이드바 변경 없음

테넌트 상세 화면(`TenantDetailPage`) 내 **`Users` 탭이 이미 존재**(`TenantDetailPage.tsx:13` `{ to: "users", label: "Users" }`). 사용자 목록은 그 탭의 `UsersTab` (이미 구현). 사이드바 변경 / 신규 메뉴 추가 **없음**.

### 5.3 사용자 목록 화면 (`UsersTab.tsx`) — 변경 없음

기존 read-only 페이지 그대로 유지. 검색 + 페이지네이션 + 행 클릭 → 상세 라우팅 모두 작동 중.

### 5.4 사용자 상세 화면 (`UserDetailPage.tsx`) — 재구성

기존 read-only 단일 화면을 **탭 구조 + 액션 가능 화면**으로 재구성. 라우트는 그대로 `/tenants/{tenantId}/users/{tenantUserId}` 유지하되 query param `?tab=credentials|sessions` 추가하여 새로고침/공유 가능.

**상단 (변경)**: 기존 `Meta` 4-grid → 상단 메타 카드 유지하되 `lastActivityAt` 카드는 그대로, "활성 Passkey 수" 카드는 status별 배지 줄로 확장:
- Active credentials / Suspended / Revoked / Active sessions 4개 배지

**하단 (신규 탭)**: `@radix-ui/react-tabs` 사용
- **Credentials** (default): 페이지네이션 테이블 (신규 `/users/{id}/credentials` endpoint 호출)
  - 컬럼: AAGUID (`AaguidLabel` — 신규 컴포넌트), Status badge, Nickname, 마지막 사용, 등록일, 액션
  - 행 액션 (shadcn DropdownMenu): Nickname 수정 (status=ACTIVE) / Revoke (status=ACTIVE) / Unsuspend (status=SUSPENDED) — 기존 endpoint 재사용. 수동 SUSPEND 액션은 제공하지 않음 (SUSPEND는 MDS 자동 파이프라인 전용)
  - 빈 상태: `EmptyState` ("이 사용자에게는 등록된 자격증명이 없습니다")
- **Sessions** (신규): 페이지네이션 테이블 (신규 `/users/{id}/refresh-tokens` endpoint)
  - 상단 컨트롤: `Segmented` (`Active only` / `All`), "모두 로그아웃" 버튼 (AlertDialog 확인 → 기존 `POST logout-all`)
  - 컬럼: Issued at, Expires at, Client IP / User agent (있을 때), Status (revoked_at 있으면 revoked badge + reason), 액션
  - 행 액션: Revoke (AlertDialog 확인 → 신규 `DELETE /refresh-tokens/{id}`) — active token에만 표시
  - 빈 상태: `EmptyState` ("활성 세션이 없습니다")

### 5.5 라우팅 — 변경 없음

`App.tsx:89`의 `<Route path="users/:tenantUserId" element={<UserDetailPage />} />` 그대로. 탭은 query param 기반이라 라우트 추가 없음.

## 6. 서버 사이드 설계 — Brownfield

### 6.1 기존 컴포넌트 재사용

| 컴포넌트 | 위치 | 사용처 |
|---|---|---|
| `TenantUserRepository.findByTenantIdWithSearch` | `tenant/repository/TenantUserRepository.java` | 기존 목록 endpoint가 이미 사용 |
| `CredentialRepository.findAllByTenantUserId` | `credential/repository/CredentialRepository.java` | 신규 paged endpoint도 같은 메서드의 paged 버전 추가하여 사용 |
| `RefreshTokenRepository.revokeAllByTenantUserId` | `auth/jwt/repository/RefreshTokenRepository.java` | 기존 logout-all이 사용 중 |
| `AdminAuthz.requireTenantAccess(UUID)` | `admin/security/AdminAuthz.java` | 신규 controller도 동일 패턴 호출 |
| `AuditService.append(...)` | `audit/service/AuditService.java` | 개별 token revoke audit log 작성 |
| `MdsBlobProvider.getLastBlob()` | `credential/metadata/MdsBlobProvider.java` | AAGUID 라벨 lookup의 데이터 소스 |
| `ApiResponse<T>`, `PageResponse<T>` | `common/response/` | 응답 wrap |

### 6.2 신규 도메인 컴포넌트

**`credential.metadata.AaguidLabelResolver`** (신규 `@Service`)
- 시그니처: `AaguidLabel resolve(UUID aaguid)` 
- 출력 record: `AaguidLabel(UUID aaguid, String displayName, boolean fromMds)`
  - `aaguid == null` → `displayName = "unknown"`, `fromMds = false`
  - MDS BLOB 매치 → `displayName = entry.metadataStatement().description()`, `fromMds = true`
  - 매치 실패 → `displayName = aaguid.toString()`, `fromMds = false` → UI에서 "미등록" 배지
- 의존성: `MdsBlobProvider`. lookup 호출당 O(N) 순회 회피 위해 내부 `volatile Map<UUID, MetadataEntry>` 캐시. 첫 호출 시 `blob.entries()` 순회로 빌드.
- 캐시 invalidate: `@EventListener(MdsBlobRefreshedEvent.class)` — 기존 `ApplicationReadyEvent` 후 발행 보장됨(직전 PR fix). blob refresh 시 캐시 클리어.

**(서비스 클래스 신규 X)** — 기존 `AdminEndUserController` / `AdminUserSessionController`처럼 신규 controller도 repository를 직접 호출하는 기존 패턴 준수. admin controller는 ArchUnit Rule 3 예외라 service layer 강제 안 함. spec의 v1 보정에서 service layer 신설은 yagni로 컷.

### 6.3 신규 Controller 1개 + 기존 Controller 1개 수정

**기존 `AdminEndUserController` 수정**:
- `EndUserDetailView` 응답에서 `credentials: List<CredentialView>` 제거 → status별 count + sessions count 객체로 대체 (4.2 spec)
- 신규 메서드 추가:
  - `GET /{tenantUserId}/credentials` paged → 새 `UserCredentialItemView`
  - `GET /{tenantUserId}/refresh-tokens` paged → 새 `RefreshTokenView`

**신규 `AdminRefreshTokenController`** (`/api/v1/admin/tenants/{tenantId}/users/{tenantUserId}/refresh-tokens` prefix)
- `DELETE /{tokenId}` — 단건 revoke. audit log 1줄.
- (controller 분리 이유: revoke는 mutating + audit. read paged는 detail controller가 처리.)

### 6.4 신규 Repository 메서드

**`CredentialRepository`** (기존 interface에 메서드 추가)
- `Page<Credential> findAllByTenantUserId(UUID tenantUserId, Pageable pageable)` — 기존 List 버전과 메서드명 같지만 Pageable 오버로드
- `long countByTenantUserIdAndStatus(UUID tenantUserId, CredentialStatus status)` — detail 응답의 카운트 계산용 (3번 호출, 또는 GROUP BY 단건 메서드 신설 — 구현 단계에서 측정 후 결정)

**`RefreshTokenRepository`** (기존 interface에 메서드 추가)
- `Page<RefreshToken> findActiveByTenantUserId(UUID tenantUserId, OffsetDateTime now, Pageable pageable)` — `revoked_at IS NULL AND expires_at > now`, `issued_at DESC` 정렬
- `Page<RefreshToken> findAllByTenantUserId(UUID tenantUserId, Pageable pageable)` — `status=all` 모드용
- `long countActiveByTenantUserId(UUID tenantUserId, OffsetDateTime now)` — detail 카운트용
- 단건 revoke는 기존 `findByIdAndTenantUserId` + `RefreshToken.revoke(...)` 도메인 메서드 + JPA 변경감지 활용 — 신규 update query 불필요

### 6.5 DTO

**기존 `EndUserDetailView` 변경** (Breaking):
```java
public record EndUserDetailView(
    UUID id, String externalId, String displayName,
    OffsetDateTime createdAt, OffsetDateTime updatedAt,
    CredentialCounts credentials,         // 신규: { active, suspended, revoked }
    SessionCounts sessions,                // 신규: { active }
    OffsetDateTime lastActivityAt          // 기존 유지
    // credentials: List<CredentialView> 필드 제거
)
public record CredentialCounts(long active, long suspended, long revoked) {}
public record SessionCounts(long active) {}
```

**신규 (paged endpoint 응답 row)**:
- `UserCredentialItemView { UUID id, String credentialIdShort, AaguidLabel aaguid, CredentialStatus status, String suspendedReason, String nickname, OffsetDateTime createdAt, OffsetDateTime lastUsedAt }` — `credentialIdShort`는 raw credential_id의 첫 8 hex chars (UI 가독성)
- `RefreshTokenView { UUID id, OffsetDateTime issuedAt, OffsetDateTime expiresAt, String clientIp, String userAgent, OffsetDateTime revokedAt, RevokedReason revokedReason }` — `last_used_at` 컬럼 없음 확정(정찰 결과). 표시 안 함.

### 6.6 권한 / 감사

- 모든 신규 endpoint: 기존 `AdminAuthz.requireTenantAccess(tenantId)` 호출 (controller 내부, 기존 패턴 — `@PreAuthorize` 안 씀)
- `DELETE refresh-tokens/{tokenId}` → audit log:
  - **신규 `AuditEventType.REFRESH_TOKEN_REVOKED` enum 값 추가** (기존 `USER_FORCE_LOGOUT`는 전체 logout 전용으로 유지. 개별 revoke는 다른 사건)
  - `actor: ADMIN`, `subjectType: "REFRESH_TOKEN"`, `subjectId: tokenId.toString()`, `payload: { tenantUserId, reason: "ADMIN_FORCED" }`
- `RevokedReason.ADMIN_FORCED` (기존 enum 값) 재사용 — 신규 enum 값 추가 없음
- 조회성 endpoint는 audit 안 함 (기존 컨벤션 — `AdminEndUserController`도 안 함)

### 6.7 호환성 / 마이그레이션

- **DB 스키마 변경 없음**
- **Breaking change 1건**: `EndUserDetailView` 응답 형식 — `credentials` 필드 제거. 클라이언트(`UserDetailPage.tsx`)와 동시 수정. v0.x 시기라 deprecation cycle 생략.
- 신규 listener(`AaguidLabelResolver`) 1개 추가 — 기존 `MdsRevocationScanListener`와 병행, 충돌 없음

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

## 8. Migration / Rollout (Brownfield 보정)

- **Phase 1 (1주차)**: 서버 — `AaguidLabelResolver` + 신규 paged endpoint 2개 + DELETE refresh-token endpoint + `EndUserDetailView` 변경 + 테스트
- **Phase 2 (2주차)**: 클라이언트 — `AaguidLabel` 컴포넌트 + 데이터 훅 + `UserDetailPage` 탭 구조 리팩토링 + Credentials 탭 (페이지 + 액션)
- **Phase 3 (3주차)**: 클라이언트 — Sessions 탭 (페이지 + 개별 revoke + 전체 logout 통합) + E2E
- **Phase 4 (4주차)**: 통합 / 폴리싱 / 운영자 onboarding 문서 갱신 (`admin/README.md`, `docs/operations.md` 해당 절)

Feature flag는 도입하지 않음 — `EndUserDetailView` Breaking change는 admin console이 유일 소비자라 단일 PR에서 동시 갱신.

## 9. 위험 / 안전장치

| 위험 | 대비 |
|------|------|
| 검색 쿼리가 큰 테이블에서 느림 | `tenant_user(external_id)` 인덱스가 이미 unique 인덱스로 존재(기존 마이그레이션) → `LIKE` 좌우 wildcard는 인덱스 불가. 페이지네이션 size 상한(100) + Oracle plan 확인 시 첫 phase 끝나면 정밀 측정. 필요 시 후속 phase에 functional index 또는 검색용 컬럼 추가. |
| AAGUID 캐시 stale | `MdsBlobRefreshedEvent` 수신 시 invalidate (이미 `ApplicationReadyEvent` 이후 발행되도록 직전 PR에서 fix됨) |
| 개별 token revoke 오작동(잘못된 사용자 token 잡힘) | endpoint path가 `/users/{tenantUserId}/refresh-tokens/{tokenId}` — service에서 `tokenId` 조회 시 `tenant_user_id` 일치 검증. 불일치 → 404. VPD가 추가 안전망. |
| Sessions 탭 페이지가 expired token으로 도배 | 기본 `status=active` 필터로 시작. `All` 토글에서만 expired 표시. |
| 신규 DTO와 기존 `CredentialView` 사이 정보 비대칭 | Diataxis "Reference" 문서에 두 응답의 의도 차이 명시 (전체 테넌트 page용 vs 사용자 scope용) |

## 10. Open Questions

정찰 단계(plan 작성 시)에서 모두 해소됨:

| 원 질문 | 결론 |
|---|---|
| `AuditEventType` 신규 값 vs 재사용 | **신규 `REFRESH_TOKEN_REVOKED` 추가**. `USER_FORCE_LOGOUT`은 전체 logout 전용으로 유지 |
| `RefreshToken.last_used_at` 컬럼 존재? | **없음**. UI에서 해당 컬럼 표시 안 함. `client_ip` / `user_agent`는 있어 대체 표시 |
| 사용자 상세 진입점 | 기존 TenantDetailPage의 Users 탭 그대로 사용. 사이드바 변경 없음 |
| `DELETE /credentials/{id}` idempotent 컨벤션 | 신규 `DELETE /refresh-tokens/{id}`는 자체 컨벤션 적용: 200 + `{ alreadyRevoked: true }` 응답 |
| 신규 `ErrorCode` | **추가 없음**. 기존 `ENTITY_NOT_FOUND` (C003) / `INVALID_INPUT` (C001) / `ADMIN_ROLE_FORBIDDEN` (M002) 재사용 (기존 `AdminEndUserController`와 동일) |

구현 시작 전 한 가지 확인 필요:
- `EndUserDetailView` Breaking change: v0.x라 deprecation 없이 동시 수정 OK인지 admin owner / API 소비자 확인 (admin console이 단일 소비자라 사실상 OK)

## 11. 변경 이력

- 2026-05-24: 최초 작성 (brainstorming v1)
- 2026-05-24: Brownfield 보정 (v1.1) — 정찰 결과 반영. 기존 `AdminEndUserController` / `UsersTab` / `UserDetailPage` 존재 사실 반영, 신규 신설로 잘못 잡혔던 항목 정리, service layer 신설 컷, ErrorCode 추가 없음으로 단순화, `EndUserDetailView` Breaking change 명시
