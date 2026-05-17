# Passkey Admin Console — PRD

> Crosscert Passkey Server (`server/`)의 운영자/RP 관리자가 사용할 웹 콘솔.
> 백엔드는 이미 `/api/v1/admin/**` REST를 제공함. 본 문서는 **그 위에 얹을 SPA의 요구사항**.

| 항목 | 값 |
|------|---|
| 코드네임 | `passkey-admin-console` |
| 백엔드 | 기존 `server/` (변경 최소) |
| 도메인 | `admin.passkey.example.com` (별도 호스트) |
| 기술 스택 | Vite 5 + React 18 + TypeScript 5 + Tailwind 3 + shadcn/ui + TanStack Query 5 + React Router 6 |
| 상태 | v1.0 PRD — 2026-05-16 |
| 대상 릴리즈 | v1.0 (MVP), v1.1 (운영 강화) |

---

## 1. 배경 & 목표

### 1.1 배경

`server/`는 멀티테넌트 Passkey 인증 백엔드로, 다음 두 부류의 운영자를 가짐:

- **PLATFORM_OPERATOR** (Crosscert 사내 운영): 모든 tenant에 대해 cross-tenant 조회/생성·관리 가능. `BYPASSRLS` `app_admin` 역할.
- **RP_ADMIN** (RP 회사 IAM 담당): 자기 회사 = `tenant_id`가 일치하는 1개 tenant만 관리. `app_runtime`(NOBYPASSRLS).

현재 운영은 cURL/Swagger UI(prod 차단) 또는 직접 SQL로 처리되고 있고, **다음 단계로 진입하려면 GUI 콘솔이 필요**하다는 판단.

### 1.2 비즈니스 목표

| 목표 | 측정 지표 |
|------|----------|
| RP 온보딩 평균 시간 단축 | tenant 생성 → 첫 API key 발급까지 < 5분 (현재 cURL 사용 ~20분) |
| RP_ADMIN 자율 운영 비율 | 자체 API key 발급/회수, credential revoke를 콘솔로 수행 (현재 0%) |
| 컴플라이언스 감사 응답 시간 | audit log 무결성 보고서 발급 < 1시간 (현재 ~1일, DBA가 직접 dump) |
| 사고 대응 (key 유출) | API key 회수 → 다음 ceremony에서 차단 확인까지 < 2분 |

### 1.3 비-목표 (out of scope, v1.0)

- 셀프 sign-up — admin은 SQL/`AdminUserSeeder` CLI로 운영자가 직접 생성. 콘솔에서 admin 사용자 CRUD는 v1.1.
- RP_ADMIN의 비밀번호 재설정 self-service — v1.1.
- 차트/대시보드의 시계열 시각화 (Grafana로 대체).
- 모바일 반응형 — desktop ≥ 1280px 우선. tablet은 best-effort.
- i18n — 한국어만. EN은 v1.1.
- SSO/OIDC — v2.

---

## 2. 사용자 / 역할

### 2.1 페르소나

**P1. 정 운영자 — Crosscert 플랫폼 운영자 (PLATFORM_OPERATOR)**
- 새 RP 온보딩, tenant 생성, 초기 WebAuthn config + AAGUID 정책 + API key 1개 발급
- 사고 시 cross-tenant 조회 (audit log, credential 등)
- 매월 무결성 보고서 출력

**P2. 김 IAM담당 — RP 회사의 IAM 담당자 (RP_ADMIN)**
- 자기 회사 tenant의 API key 발급/회수 (rotation 정책)
- WebAuthn config 변경 (origin 추가 등)
- 특정 사용자의 credential revoke (사고 시)
- audit log 조회 (자기 tenant 내)

### 2.2 권한 매트릭스

| 기능 | PLATFORM_OPERATOR | RP_ADMIN |
|------|-------------------|----------|
| `GET /me` | ✅ | ✅ |
| `GET /tenants` (전체) | ✅ | ❌ (자기 tenant만 자동 라우팅) |
| `POST /tenants` | ✅ | ❌ |
| `GET /tenants/{id}` | ✅ (any) | ✅ (자기 tenant만) |
| `GET/PUT /tenants/{id}/webauthn-config` | ✅ | ✅ (자기 tenant) |
| `GET/PUT /tenants/{id}/attestation-policy` | ✅ | ✅ (자기 tenant) |
| `GET/POST/DELETE /tenants/{id}/api-keys` | ✅ | ✅ (자기 tenant) |
| `GET/DELETE /tenants/{id}/credentials` | ✅ | ✅ (자기 tenant) |
| `GET /tenants/{id}/audit-logs` | ✅ | ✅ (자기 tenant) |
| `GET /tenants/{id}/audit-logs/verify` | ✅ | ✅ (자기 tenant) |
| `GET /tenants/{id}/funnel` | ✅ | ✅ (자기 tenant) |

→ 서버가 이미 `AdminAuthz.requireTenantAccess(tenantId)` / `requirePlatformOperator()`로 강제. **콘솔은 권한 게이트를 추가로 보여주는(UX) 역할이지 보안 게이트가 아님**.

---

## 3. 사용자 여정 (Key User Flows)

### F-1. PLATFORM_OPERATOR: 새 RP 온보딩 (~5분)

```
로그인 → /tenants 목록 → "신규 tenant" → name + slug 입력 → 생성
       → tenant 상세 → WebAuthn config 설정 (rpId, origins, UV) → 저장
       → AAGUID 정책 설정 (ANY로 시작 권장) → 저장
       → API keys → 발급 → ⚠️ plaintext 1회 노출 모달 → "복사 완료" 확인
       → tenant 상세 페이지에서 funnel/audit 빈 상태 확인
```

### F-2. RP_ADMIN: API key rotation (~2분)

```
로그인 → 자동으로 자기 tenant 상세 → API keys 탭
       → 새 키 발급 → plaintext 복사 → RP 서비스에 배포
       → 기존 키 "회수" → revoked 표시 확인
       → audit log 탭에서 API_KEY_ISSUED / API_KEY_REVOKED 행 확인
```

### F-3. RP_ADMIN: 사고 대응 — 사용자 credential 회수 (~1분)

```
로그인 → credentials 탭 → externalUserId 검색 → 해당 credential 행 "revoke"
       → 확인 다이얼로그 (credentialId 마지막 8자 표시) → 확인
       → 상태가 REVOKED로 변경 → audit log 행 확인
```

### F-4. PLATFORM_OPERATOR: 월간 무결성 보고서 (~3분)

```
로그인 → tenant 선택 → audit log 탭 → "Hash chain 검증" 버튼
       → 날짜 범위 (전월 1일 ~ 말일) → 실행
       → 결과 카드: verifiedRows N건 / tamperedEntryIds [] (정상)
       → "PDF 다운로드" 또는 화면 캡처
       → 동일 작업을 다른 tenant에도 반복 (or scheduler 결과만 확인)
```

---

## 4. 기능 요구사항 (REQ)

각 REQ는 우선순위(P0/P1/P2)와 매핑된 백엔드 endpoint를 명시. P0 = MVP 필수.

### 4.1 인증

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-A-1 | P0 | 이메일 + 비밀번호 로그인 폼. 성공 시 `JSESSIONID` 쿠키 발급(서버가 자동), `/me` 호출 후 메인으로 리다이렉트 | `POST /api/v1/admin/auth/login` |
| REQ-A-2 | P0 | 로그아웃 버튼. 세션 무효화 후 로그인 화면으로 | `POST /api/v1/admin/auth/logout` |
| REQ-A-3 | P0 | `/me` 응답 캐싱 — TanStack Query로 5분 stale, 401 응답 시 자동 로그아웃 + redirect | `GET /api/v1/admin/me` |
| REQ-A-4 | P0 | CSRF: 모든 mutation 호출 직전에 `XSRF-TOKEN` 쿠키 값을 `X-XSRF-TOKEN` 헤더에 echo (axios/fetch interceptor) | (Spring Security CSRF) |
| REQ-A-5 | P1 | 30분 idle 후 세션 만료 안내 모달 → 재로그인 유도 | — |

### 4.2 글로벌 레이아웃

| ID | 우선 | 설명 |
|----|------|------|
| REQ-L-1 | P0 | 좌측 사이드바: PLATFORM_OPERATOR면 "Tenants" 최상위, RP_ADMIN이면 자기 tenant 이름이 최상위로 표시 |
| REQ-L-2 | P0 | 상단 헤더: 현재 운영자 이메일 + role 배지 + 로그아웃 |
| REQ-L-3 | P0 | Toast 알림 (성공/에러). 에러는 `code` (예: `A002`) + `message`를 보여주고 traceId 표시 (디버깅용) |
| REQ-L-4 | P0 | breadcrumb: `Tenants / 테스트카드 / API Keys` 형태 |
| REQ-L-5 | P1 | 좌측 사이드바에 "audit chain status" 인디케이터 (마지막 scheduler 결과, prometheus 연동) — v1.1 |

### 4.3 Tenants

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-T-1 | P0 | PLATFORM_OPERATOR: tenant 목록 (page=0, size=50) — name, slug, status, createdAt | `GET /api/v1/admin/tenants?page=&size=` |
| REQ-T-2 | P0 | PLATFORM_OPERATOR: 새 tenant 생성 모달 — name + slug (`^[a-z][a-z0-9-]{1,62}$` 클라이언트 validation + 서버 정합성) | `POST /api/v1/admin/tenants` |
| REQ-T-3 | P0 | tenant 상세 페이지 — 메타 카드 + 탭(WebAuthn / AAGUID / API Keys / Credentials / Audit / Funnel) | `GET /api/v1/admin/tenants/{id}` |
| REQ-T-4 | P0 | RP_ADMIN 로그인 시 자동으로 `/tenants/{내 tenantId}`로 리다이렉트 — 목록 화면 노출 안 함 | — |
| REQ-T-5 | P1 | tenant 검색/필터 (slug substring) — v1.1 |

### 4.4 WebAuthn Config

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-W-1 | P0 | 현재 config 카드: rpId, rpName, origins 목록, timeoutMs, userVerification, attestationConveyance | `GET /api/v1/admin/tenants/{id}/webauthn-config` |
| REQ-W-2 | P0 | 편집 폼: 모든 필드 inline 편집. origins는 chip 입력. UV/AC는 select. validation: rpId 비어있지 않음, origins ≥ 1, timeoutMs > 0 | `PUT /api/v1/admin/tenants/{id}/webauthn-config` |
| REQ-W-3 | P0 | 저장 직전 변경 사항 확인 (diff 표시) — origins 변경은 라이브 RP에 영향 |
| REQ-W-4 | P1 | rpId 변경 시 큰 경고: "이 변경은 기존 모든 credential을 무효화시킬 수 있음" |

### 4.5 AAGUID / Attestation Policy

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-P-1 | P0 | 현재 정책: mode(ANY/ALLOWLIST/DENYLIST), allowed/denied 목록, mdsStrict | `GET /api/v1/admin/tenants/{id}/attestation-policy` |
| REQ-P-2 | P0 | 편집 폼: mode select + AAGUID chip 입력 (UUID 형식 validation) + mdsStrict 토글 | `PUT /api/v1/admin/tenants/{id}/attestation-policy` |
| REQ-P-3 | P1 | AAGUID 입력 시 자동으로 알려진 제조사 이름 매핑 표시 (FIDO MDS BLOB 기반, server `/_diag/mds-status` 활용) |

### 4.6 API Keys

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-K-1 | P0 | 키 목록: prefix, name, status, createdAt. plaintext는 **절대** 표시되지 않음 | `GET /api/v1/admin/tenants/{id}/api-keys` |
| REQ-K-2 | P0 | 신규 발급 모달: name 입력 → 발급 결과 **plaintext를 1회만 노출**. "복사" 버튼 + "닫음" 시 영구 소실. 닫기 전 confirm 다이얼로그 ("복사하셨나요?") | `POST /api/v1/admin/tenants/{id}/api-keys` |
| REQ-K-3 | P0 | 회수 버튼 — 확인 다이얼로그 (prefix 표시) → 회수 후 status REVOKED로 즉시 반영 | `DELETE /api/v1/admin/tenants/{id}/api-keys/{keyId}` |
| REQ-K-4 | P0 | 회수된 키는 행이 회색 처리 + 상단으로 가지 않고 정렬 유지 |
| REQ-K-5 | P1 | "마지막 사용 일시" 컬럼 (서버에 데이터 있음 — `lastUsedAt`) — DTO 확장 후 v1.1 |

### 4.7 Credentials

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-C-1 | P0 | 페이지된 목록: credentialId(마지막 12자), externalUserId, nickname, status, aaguid, transports, signatureCounter, lastUsedAt, createdAt | `GET /api/v1/admin/tenants/{id}/credentials?page=&size=` |
| REQ-C-2 | P0 | externalUserId substring 검색 (서버 supports) |
| REQ-C-3 | P0 | revoke 버튼 — 확인 다이얼로그 (credentialId 마지막 12자) → REVOKED | `DELETE /api/v1/admin/tenants/{id}/credentials/{credentialId}` |
| REQ-C-4 | P1 | aaguid 컬럼은 MDS 매핑된 제조사 이름 표시 (있으면) |

### 4.8 Audit Log + Chain Verification

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-D-1 | P0 | 페이지된 목록: createdAt, eventType, actorType, actorId(마지막 8자), subjectType, subjectId(마지막 8자), payload(JSON preview, 클릭 시 모달 full view) | `GET /api/v1/admin/tenants/{id}/audit-logs?page=&size=` |
| REQ-D-2 | P0 | eventType 필터 (`API_KEY_ISSUED`, `CREDENTIAL_AUTHENTICATED` 등) — 클라이언트 측 필터 (v1.0), 서버 필터 추가는 v1.1 |
| REQ-D-3 | P0 | "Hash chain 검증" 버튼 → 날짜 범위 picker (기본 from=어제 to=오늘) → 실행 | `GET /api/v1/admin/tenants/{id}/audit-logs/verify?from=&to=` |
| REQ-D-4 | P0 | 검증 결과 카드: `intact` 배지 (초록/빨강), `verifiedRows`, `tamperedEntryIds` 목록 (있으면 행을 audit log 목록에서 하이라이트) |
| REQ-D-5 | P1 | 검증 결과 PDF/PNG 내보내기 — v1.1 |

### 4.9 Funnel

| ID | 우선 | 설명 | API |
|----|------|------|-----|
| REQ-F-1 | P0 | 카드: 등록 시도/성공, 인증 시도/성공, 등록→인증 전환율. 기간 select (24h/7d/30d) | `GET /api/v1/admin/tenants/{id}/funnel?windowDays=` |
| REQ-F-2 | P1 | 시계열 chart (recharts) — v1.1 |

---

## 5. 비기능 요구사항 (NFR)

### 5.1 보안

| ID | 항목 |
|----|------|
| NFR-S-1 | 빌드 산출물(`dist/`)은 시크릿/환경별 값을 포함하지 않음. `VITE_API_BASE_URL`만 `.env.production`에서 주입 — admin 서버 도메인 |
| NFR-S-2 | `fetch credentials: 'include'`로 cross-origin 쿠키 전송. CORS는 서버 측에서 `admin.passkey.example.com`만 allowlist + `Access-Control-Allow-Credentials: true` (실행계획서 task 참고) |
| NFR-S-3 | XSS 방어: React 기본 escape + dangerouslySetInnerHTML 금지 ESLint 룰 |
| NFR-S-4 | localStorage/sessionStorage에 **세션 토큰 / API key plaintext / CSRF 토큰 저장 금지**. 쿠키는 서버가 관리, CSRF는 메모리에 잠시 캐싱만 |
| NFR-S-5 | Content Security Policy: 서버가 이미 `default-src 'none'` 등 strict 헤더 발급. SPA 자산은 self origin만 — CSS/JS는 동일 도메인에서 서빙 |
| NFR-S-6 | 보안 헤더 (HSTS, X-Frame-Options=DENY, Referrer-Policy=no-referrer)는 nginx 단에서 SPA serve 시 명시 |

### 5.2 가용성/성능

| ID | 항목 |
|----|------|
| NFR-P-1 | 초기 로딩(빈 캐시, 빠른 4G 가정) < 2s. 빌드 산출물 < 500KB gzipped (lazy split) |
| NFR-P-2 | 페이지 라우팅 < 200ms (code splitting + suspense) |
| NFR-P-3 | TanStack Query 기본 staleTime = 30s, mutation 후 affected query invalidate |
| NFR-P-4 | API 호출 timeout = 15s. timeout / 5xx 발생 시 retry 1회 (idempotent GET only) |

### 5.3 운영

| ID | 항목 |
|----|------|
| NFR-O-1 | nginx 정적 호스팅. Docker 이미지 `passkey-admin-console:<version>` — `nginx:alpine` base, ~30MB |
| NFR-O-2 | SPA fallback: 모든 `/*` → `index.html` (React Router) |
| NFR-O-3 | 환경별 `VITE_API_BASE_URL`: dev=`http://localhost:8080`, prod=`https://api.passkey.example.com` |
| NFR-O-4 | 로그: 브라우저 console만, 별도 telemetry는 v1.1 (Sentry 등) |
| NFR-O-5 | Healthcheck endpoint: nginx `/healthz` → 200 |

### 5.4 접근성/품질

| ID | 항목 |
|----|------|
| NFR-A-1 | 키보드 내비게이션 — 모든 mutation 버튼 Tab 도달 가능 |
| NFR-A-2 | Lighthouse Accessibility ≥ 90 (Best practices ≥ 85) |
| NFR-A-3 | 한국어 글꼴: 시스템 ui sans-serif → Pretendard fallback. CDN 의존 없이 self-host |

---

## 6. UX / IA

### 6.1 정보 구조

```
Login (/)
  │
  └── App (authenticated, layout)
        ├── /tenants                            (PLATFORM_OPERATOR only — list)
        ├── /tenants/:tenantId                  (overview)
        │     ├── /webauthn-config              (read + edit)
        │     ├── /attestation-policy           (read + edit)
        │     ├── /api-keys                     (list + issue modal + revoke)
        │     ├── /credentials                  (paged list + search + revoke)
        │     ├── /audit-logs                   (paged list + verify modal)
        │     └── /funnel                       (cards)
        └── /me                                 (profile, 로그아웃)
```

RP_ADMIN 로그인 시 `/` → `/tenants/{내 tenantId}`로 자동 redirect.

### 6.2 디자인 원칙

- shadcn/ui 기본 — Radix primitives + Tailwind. 색상 토큰은 neutral(slate) 베이스 + accent(blue-600).
- **위험한 액션은 항상 confirm 다이얼로그**. revoke / delete는 대상 식별자 마지막 N자를 보여주고 입력하도록 (옵션, v1.1).
- API key 발급 직후 plaintext 노출 모달은 **닫기 전 "복사 완료" 체크박스 강제**.
- 빈 상태(EmptyState)는 명시적: "아직 발급된 API key가 없습니다." + primary CTA.

### 6.3 와이어프레임 (텍스트)

**Login**
```
┌─────────────────────────────┐
│  Crosscert Passkey Admin    │
│                             │
│  Email     [____________]   │
│  Password  [____________]   │
│                             │
│           [  로그인  ]      │
└─────────────────────────────┘
```

**Tenant Detail — API Keys**
```
┌──────────────────────────────────────────────────────────────┐
│ Tenants > 테스트카드                              [ jhyun@ ▾ ]│
├──────────────────────────────────────────────────────────────┤
│ [ WebAuthn ][ AAGUID ][API Keys][ Credentials ][ Audit ][... ]│
├──────────────────────────────────────────────────────────────┤
│ API Keys                                  [ + 새 키 발급 ]   │
│                                                              │
│  Prefix       Name         Status      Created     Actions   │
│  aB3xY7Q9     production   ACTIVE      2026-05-15  [ 회수 ]  │
│  zZ91qq2P     staging      ACTIVE      2026-05-10  [ 회수 ]  │
│  oldKeyAA     old-rotated  REVOKED     2026-04-01     —      │
└──────────────────────────────────────────────────────────────┘
```

**Issued Key Modal (1회 노출)**
```
┌──────────────────────────────────────────────────────────────┐
│ ⚠️  새 API key가 발급되었습니다 — 지금만 표시됩니다              │
│                                                              │
│  pk_aB3xY7Q9.7M9bK2pXq...vN3jL                  [ 📋 복사 ]  │
│                                                              │
│  ☐ 안전한 곳에 복사했습니다                                   │
│                                          [ 닫기 (체크 필요) ] │
└──────────────────────────────────────────────────────────────┘
```

---

## 7. 백엔드 변경 영향

본 콘솔을 위해 서버에 필요한 변경 (실행계획서에 세부 task로 분리):

| 변경 | 필요성 |
|------|--------|
| **CORS 설정** — `admin.passkey.example.com` allowlist + `Access-Control-Allow-Credentials: true` + 허용 헤더(`X-XSRF-TOKEN`, `Content-Type`) + 허용 메서드(GET/POST/PUT/DELETE) | 별도 도메인 SPA가 세션 쿠키 전송하기 위해 필수 |
| **Session cookie SameSite=None** (별도 도메인 한정) — 단 prod에서만, local은 lax 유지 | 별도 도메인이면 SameSite=Lax는 cross-site 요청에 동작 안 함. `SameSite=None; Secure`로 변경 필요 (또는 같은 etld+1 도메인 사용) |
| **CSRF 쿠키 SameSite=None** — 동일 이유 | |
| **`/api/v1/admin/auth/me` 응답 풍부화** — 현재 `Me(adminId, role, tenantId, displayName)` 충분, 추가 변경 없음 | — |
| **(v1.1) Credentials 검색 endpoint** — 현재 `findAll`만 있음. `?externalUserId=` query param 추가 필요 | REQ-C-2 |
| **(v1.1) Audit eventType 서버 필터** — `?eventType=` query param | REQ-D-2 |
| **(v1.1) AdminUser CRUD endpoint** — 운영자 self-service | — |

---

## 8. 마일스톤 (요약, 실행계획서가 정본)

| 마일스톤 | 기간 | 산출물 |
|----------|------|--------|
| M0 — 인프라/스캐폴딩 | 3일 | Vite repo, CI/CD, nginx Dockerfile, 서버 CORS/cookie 변경 |
| M1 — 인증 + 레이아웃 | 4일 | 로그인/로그아웃/me, 사이드바, 라우팅, 권한 가드 |
| M2 — Tenant CRUD + WebAuthn config + AAGUID | 4일 | REQ-T-*, REQ-W-*, REQ-P-* |
| M3 — API Key + Credentials | 4일 | REQ-K-*, REQ-C-* (revoke 다이얼로그 포함) |
| M4 — Audit + Funnel | 3일 | REQ-D-*, REQ-F-* (verify 결과 표시 포함) |
| M5 — Polishing + 운영 | 3일 | 에러 처리, 한국어 카피, Lighthouse ≥90, deploy runbook |

**총 ~21 영업일 (≈ 4주, 1인 풀타임 기준)**.

---

## 9. 성공 기준 (Acceptance, v1.0)

다음 모두 만족 시 v1.0 출시:

1. **F-1 ~ F-4 user flow가 콘솔만으로 완수 가능** (cURL 사용 0건)
2. **모든 P0 REQ 구현 + e2e 시나리오 통과** (Playwright happy path)
3. **CORS / 세션 / CSRF 동작 검증** — 별도 도메인에서 로그인 → mutation → 로그아웃까지 cookie/header 흐름이 깨지지 않음
4. **Lighthouse**: Performance ≥ 80, Accessibility ≥ 90, Best Practices ≥ 85 on `/tenants/:id/api-keys`
5. **무결성 검증 PDF/캡처** — 운영자가 콘솔만으로 월간 audit chain 보고서 출력
6. **사고 대응 SLA**: API key 회수 후 다음 verify 호출 ≤ 5초 안에 401 응답 (서버 pub/sub + 캐시 evict 기존 동작 확인)
7. **architecture.md §11 변경 이력**에 admin console v1.0 항목 추가

---

## 10. 위험 & 대응

| 위험 | 가능성 | 영향 | 대응 |
|------|--------|------|------|
| SameSite=None 도입으로 다른 cross-site에서 쿠키 노출 | 중 | 중 | `Secure` 필수 + `Domain` 명시 + CSRF로 mitigated |
| 다른 도메인에서 세션 cookie 전송이 brave/safari 등에서 차단 | 중 | 고 | 같은 etld+1 (`*.passkey.example.com`) 사용으로 Lax 유지 가능 — 운영자가 도메인 정책 결정 (실행계획서 task) |
| API key plaintext 노출 모달을 사용자가 실수로 닫음 | 고 | 중 | "복사 완료" 체크박스 강제 + 닫기 후 재발급 안내 + audit log 남김 |
| RP_ADMIN이 잘못 로그인해 다른 tenant 시도 — 403 무한 루프 | 저 | 저 | `/me` 응답의 tenantId로 자동 라우팅 + 권한 없는 path는 fallback |
| Vite 환경변수 누출 (`VITE_*`는 빌드 산출물에 박힘) | 중 | 저 | 시크릿 절대 미주입. `VITE_API_BASE_URL`만 박음 (공개 정보) |
| 별도 도메인 → CSP 위반 | 중 | 중 | 서버 CSP는 admin 경로만 적용; admin 도메인은 nginx에서 별도 CSP 발급 |

---

## 11. 의사결정 기록

| 결정 | 대안 | 채택 이유 |
|------|------|----------|
| Vite + React SPA | Next.js 14 | admin은 인터널 툴 (SEO/SSR 가치 없음), 정적 nginx 1개로 끝, 모든 액션 mutation 위주 — RSC 이점 미미. Node 서버 운영 부담 회피 |
| shadcn/ui | MUI, Mantine | Tailwind와 자연스러운 통합, copy-paste 컴포넌트 모델로 종속성 최소화 |
| TanStack Query | Redux Toolkit, SWR | mutation+invalidate 패턴이 admin 화면에 정확히 부합. cache key는 endpoint 그대로 |
| 별도 도메인 `admin.passkey.example.com` | 같은 도메인 하위 경로 `/admin/` | 운영 분리 명확, 단 cookie SameSite는 None 필요 → 별도 task로 처리 |
| Full 2 roles MVP | Platform Operator 우선 | RP_ADMIN 자율 운영이 비즈니스 목표 핵심 |
| `/admin-console-docs/` 별도 디렉터리 | 기존 `docs/` 통합 | admin-console은 별 repo로 분리 가능성 있음 — 격리 유지 |

---

## 12. 부록 — 백엔드 API 카탈로그 (참고)

| Method | Path | 권한 | DTO |
|--------|------|------|-----|
| POST | `/api/v1/admin/auth/login` | public | `{email, password}` |
| POST | `/api/v1/admin/auth/logout` | session | — |
| GET | `/api/v1/admin/me` | session | `Me{adminId, role, tenantId, displayName}` |
| GET | `/api/v1/admin/tenants?page=&size=` | PLATFORM_OPERATOR | `PageResponse<TenantView>` |
| POST | `/api/v1/admin/tenants` | PLATFORM_OPERATOR | `{name, slug}` |
| GET | `/api/v1/admin/tenants/{id}` | tenantAccess | `TenantView` |
| GET/PUT | `/api/v1/admin/tenants/{id}/webauthn-config` | tenantAccess | `ConfigView` |
| GET/PUT | `/api/v1/admin/tenants/{id}/attestation-policy` | tenantAccess | `PolicyView` |
| GET | `/api/v1/admin/tenants/{id}/api-keys` | tenantAccess | `List<ApiKeyView>` |
| POST | `/api/v1/admin/tenants/{id}/api-keys` | tenantAccess | `{name}` → `IssuedKeyView{id, plaintext, prefix, name}` |
| DELETE | `/api/v1/admin/tenants/{id}/api-keys/{keyId}` | tenantAccess | 204 |
| GET | `/api/v1/admin/tenants/{id}/credentials?page=&size=` | tenantAccess | `PageResponse<CredentialView>` |
| DELETE | `/api/v1/admin/tenants/{id}/credentials/{credentialId}` | tenantAccess | 204 |
| GET | `/api/v1/admin/tenants/{id}/audit-logs?page=&size=` | tenantAccess | `PageResponse<AuditView>` |
| GET | `/api/v1/admin/tenants/{id}/audit-logs/verify?from=&to=` | tenantAccess | `ChainVerification` |
| GET | `/api/v1/admin/tenants/{id}/funnel?windowDays=` | tenantAccess | `FunnelView` |

모든 응답은 `ApiResponse<T>` envelope: `{success, code, message, data, error, traceId, timestamp}`. 에러 코드는 `docs/error-codes.md` 참조.
