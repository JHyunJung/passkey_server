# Passkey Admin Console — Action Plan

> [admin-console-prd.md](./admin-console-prd.md)의 P0~P1을 v1.0으로 실현하기 위한 **위크 단위 실행계획**.
> 1인 풀타임 기준 4주 (~21 영업일). 2인 병행 시 ~2.5주.

| 마일스톤 | 기간 | 게이트 |
|----------|------|--------|
| M0 — 인프라 & 백엔드 호환 변경 | D1–D3 (3일) | `dev` 환경에서 로그인 → `/me` 호출 성공 |
| M1 — 인증 + 레이아웃 + 권한 가드 | D4–D7 (4일) | 양 role 로그인 + 자동 라우팅 동작 |
| M2 — Tenant + WebAuthn config + AAGUID | D8–D11 (4일) | F-1 (RP 온보딩) e2e 통과 |
| M3 — API Key + Credentials | D12–D15 (4일) | F-2, F-3 e2e 통과 |
| M4 — Audit + Funnel | D16–D18 (3일) | F-4 (월간 보고서) e2e 통과 |
| M5 — Polishing + Deploy | D19–D21 (3일) | Lighthouse 통과 + 운영 runbook 완료 |

---

## M0 — 인프라 & 백엔드 호환 변경 (D1–D3)

### M0-T1. Repo 부트스트랩 (0.5일)

```bash
mkdir -p /Users/jhyun/Git/10-work/crosscert/Passkey/admin-console
cd admin-console
npm create vite@latest . -- --template react-ts
npm i -D tailwindcss postcss autoprefixer @types/node
npx tailwindcss init -p
npm i @tanstack/react-query react-router-dom zod axios date-fns
npm i -D @types/react @types/react-dom eslint-plugin-react eslint-plugin-react-hooks vitest @testing-library/react @playwright/test
```

shadcn 셋업:
```bash
npx shadcn@latest init   # base = neutral, accent = blue
npx shadcn@latest add button input form table dialog toast tabs select badge dropdown-menu pagination
```

**산출물**:
- `package.json` — Vite 5, React 18, TS 5, Tailwind 3, TanStack Query 5, React Router 6
- `tsconfig.json` — strict, paths alias `@/*` → `src/*`
- `tailwind.config.ts` — shadcn 색상 토큰 통합
- `vite.config.ts` — `server.proxy`로 `/api` → `http://localhost:8080` 프록시 (dev 시 same-origin처럼 동작)
- `.env.development` — `VITE_API_BASE_URL=` (프록시 통해 빈 문자열로 same-origin 호출)
- `.env.production` — `VITE_API_BASE_URL=https://api.passkey.example.com`

### M0-T2. CI/CD 스캐폴딩 (0.5일)

`.github/workflows/admin-console.yml`:
```yaml
on:
  pull_request:
    paths: [admin-console/**]
  push:
    branches: [main]
    paths: [admin-console/**]
jobs:
  build-test:
    steps:
      - npm ci
      - npm run lint
      - npm run typecheck     # tsc --noEmit
      - npm run test          # vitest
      - npm run build         # vite build
      - npx playwright install --with-deps   # e2e job split optional
      - npm run e2e           # 별 게이트로 분리 추천
```

**산출물**:
- GitHub Actions workflow
- `admin-console/Dockerfile` (`nginx:alpine` base):
  ```dockerfile
  FROM node:20-alpine AS build
  WORKDIR /app
  COPY package*.json ./
  RUN npm ci
  COPY . .
  ARG VITE_API_BASE_URL
  ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
  RUN npm run build

  FROM nginx:alpine
  COPY --from=build /app/dist /usr/share/nginx/html
  COPY nginx.conf /etc/nginx/conf.d/default.conf
  EXPOSE 80
  HEALTHCHECK CMD wget -qO- http://localhost/healthz || exit 1
  ```
- `nginx.conf`:
  - `try_files $uri /index.html;` (SPA fallback)
  - 보안 헤더: `add_header Strict-Transport-Security ...`, `X-Frame-Options DENY`, `X-Content-Type-Options nosniff`, `Referrer-Policy no-referrer`, CSP는 `default-src 'self'; connect-src 'self' https://api.passkey.example.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:` (Tailwind inline style 때문에 unsafe-inline 불가피)
  - `/healthz` → `return 200`

### M0-T3. 백엔드 CORS / Cookie SameSite 변경 (1일) — **블로커 task**

서버에 다음 변경이 필요. PR로 분리 — admin-console 작업 시작 전에 머지.

**`server/src/main/java/com/crosscert/passkey/admin/security/AdminSecurityConfig.java`**:
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
  CorsConfiguration cfg = new CorsConfiguration();
  cfg.setAllowedOrigins(List.of(adminConsoleOrigin));  // e.g. https://admin.passkey.example.com
  cfg.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
  cfg.setAllowedHeaders(List.of("Content-Type","X-XSRF-TOKEN","X-Trace-Id"));
  cfg.setAllowCredentials(true);
  cfg.setMaxAge(Duration.ofHours(1));
  UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
  src.registerCorsConfiguration("/api/v1/admin/**", cfg);
  return src;
}
// adminFilterChain 내부:
.cors(c -> c.configurationSource(corsConfigurationSource()))
```

**`server/src/main/resources/application-prod.yml`**:
```yaml
passkey:
  admin:
    console-origin: ${PASSKEY_ADMIN_CONSOLE_ORIGIN:https://admin.passkey.example.com}
server:
  servlet:
    session:
      cookie:
        same-site: none   # SameSite=Lax → None (cross-site cookie 전송)
        secure: true       # SameSite=None은 Secure 필수
```

**`AdminSecurityConfig.adminFilterChain` 안의 CSRF cookie**:
```java
csrfRepo.setCookieCustomizer(c ->
    c.secure(cookieSecure).sameSite("None").path("/").domain(".passkey.example.com"));
// path를 / 로 풀어 admin console 도메인에서도 도달; domain 명시로 etld+1 공유
```

**대안 (운영자 결정 필요)**: 같은 etld+1(`*.passkey.example.com`)로 묶고 `SameSite=Lax` 유지. PRD 위험 §10 참조 — 운영팀과 도메인 정책 합의 후 둘 중 하나 채택.

**검증**:
- `curl -i -X OPTIONS -H "Origin: https://admin.passkey.example.com" -H "Access-Control-Request-Method: POST" https://api.passkey.example.com/api/v1/admin/auth/login` → 200 + `Access-Control-Allow-Origin: https://admin.passkey.example.com` + `Access-Control-Allow-Credentials: true`
- Spring Boot 통합 테스트 `slice/admin/AdminCorsTest` 신규 추가

### M0-T4. 환경 변수 / 비밀 정책 (0.5일)

| 변수 | 환경 | 값 | 비고 |
|------|------|---|------|
| `VITE_API_BASE_URL` | build-time | dev: `''` (proxy), prod: `https://api.passkey.example.com` | 빌드 시 박힘 |
| `PASSKEY_ADMIN_CONSOLE_ORIGIN` | server prod env | `https://admin.passkey.example.com` | CORS allowlist |
| `PASSKEY_COOKIE_SECURE` | server prod env | `true` | SameSite=None은 Secure 필수 |

**산출물**: `.env.example` 양쪽 (client/server) + deployment runbook 초안 (`admin-console-docs/deployment.md` v0.1)

### M0 종료 게이트

- [ ] `npm run dev` → `http://localhost:5173` 띄움. Vite proxy로 `/api/v1/admin/me` 호출 → 401 응답 정상 수신 (인증 전이라 401)
- [ ] 서버 PR (CORS + SameSite=None) `./gradlew check` 통과 + merged
- [ ] `docker build` → `passkey-admin-console:0.0.1` 이미지 생성
- [ ] CI workflow가 PR마다 lint/typecheck/test/build 통과

---

## M1 — 인증 + 레이아웃 + 권한 가드 (D4–D7)

### M1-T1. API 클라이언트 + 공통 fetch (0.5일)

`src/lib/api.ts`:
- axios 인스턴스 with `baseURL`, `withCredentials: true`, 15s timeout
- Request interceptor: `XSRF-TOKEN` 쿠키 값을 `X-XSRF-TOKEN` 헤더로 echo
- Response interceptor:
  - 401 → `queryClient.setQueryData(['me'], null)` + redirect to `/`
  - 5xx → Sentry log (v1.1) + toast
- 모든 응답 unwrapper: `ApiEnvelope<T>` → `T` (SDK의 `PasskeyClient.unwrap` 패턴 차용 — `server/sdk/src/PasskeyClient.ts` 참고)
- 에러 클래스: `PasskeyAdminError(code, message, traceId)` — toast에서 code+message+traceId 노출

### M1-T2. TanStack Query provider + 라우터 (0.5일)

`src/main.tsx`:
- `QueryClient`: defaultOptions `staleTime: 30_000, retry: (n, e) => n<1 && e.status>=500`
- `BrowserRouter` + `<RouterProvider>` 또는 `<Routes>`. lazy import로 각 페이지 코드 분리

### M1-T3. 인증 페이지 + `/me` 훅 (1일)

- `src/pages/LoginPage.tsx`:
  - email/password 폼 (react-hook-form + zod)
  - submit → `POST /api/v1/admin/auth/login` (Content-Type: application/json — `JsonLoginAuthenticationFilter`가 받음)
  - 성공: `queryClient.invalidateQueries(['me'])` → 그 결과로 라우터가 자동 리다이렉트
  - 실패: 코드별 토스트 (A001 잘못된 자격, R001 rate limit)
- `src/hooks/useMe.ts`:
  - `useQuery({ queryKey: ['me'], queryFn: () => api.get('/api/v1/admin/me').then(unwrap), staleTime: 5*60_000 })`
- `src/lib/guard.tsx` — `<RequireAuth>` / `<RequirePlatformOperator>` 컴포넌트:
  - me가 로딩 중이면 spinner
  - 401 (me=null) → `<Navigate to="/" />`
  - role 불일치 → `<Navigate to="/tenants/{me.tenantId}" />` (RP_ADMIN인데 platform 전용 페이지 접근 시)

### M1-T4. 글로벌 레이아웃 (1.5일)

- `src/layout/AppLayout.tsx`: 사이드바 + 헤더 + content. shadcn `<DropdownMenu>` for me menu
- 사이드바 항목 (role에 따라 분기):
  - PLATFORM_OPERATOR: "Tenants" → `/tenants`
  - RP_ADMIN: 사이드바 최상위가 자기 tenant 이름 — `/tenants/{me.tenantId}` 로 직행
- Toast: shadcn `<Toaster>` + `useToast()` 글로벌
- breadcrumb: `useLocation` + 라우트 파라미터로 동적 구성

### M1-T5. 로그아웃 흐름 (0.5일)

- `useLogout` 훅: `POST /logout` 호출 → 세션 무효화 → `queryClient.clear()` + `Navigate('/')`
- 401 자동 로그아웃과 동일 경로 사용

### M1 종료 게이트

- [ ] PLATFORM_OPERATOR 계정으로 로그인 → `/tenants` 자동 이동
- [ ] RP_ADMIN 계정으로 로그인 → `/tenants/{내 tenantId}` 자동 이동
- [ ] RP_ADMIN이 `/tenants` 직접 URL 입력 → 자기 tenant 페이지로 redirect
- [ ] 401 응답 발생 시 자동 로그아웃 + redirect
- [ ] 로그아웃 → 세션 쿠키 삭제 확인

---

## M2 — Tenant + WebAuthn config + AAGUID (D8–D11)

### M2-T1. Tenant 목록 + 상세 (1.5일)

- `src/pages/TenantsListPage.tsx` (PLATFORM_OPERATOR only):
  - `useQuery(['tenants', { page, size }], ...)` → `PageResponse<TenantView>`
  - shadcn `<Table>` + pagination, 행 클릭 → 상세
  - "신규 tenant" 버튼 → 모달
- 신규 tenant 모달:
  - react-hook-form + zod (`name: nonEmpty, slug: regex /^[a-z][a-z0-9-]{1,62}$/`)
  - submit → `POST /api/v1/admin/tenants` → 성공 토스트 + `invalidate(['tenants'])` + 모달 close
  - 409 (slug duplicate, T004) → field error
- `src/pages/TenantDetailPage.tsx`:
  - `useQuery(['tenant', tenantId], () => GET /tenants/{id})` → 메타 카드
  - 하위 탭은 React Router nested route

### M2-T2. WebAuthn config (1일)

- `src/pages/tenant/WebauthnConfigTab.tsx`:
  - GET → form with current values
  - origins는 chip input (`<Input>` + Enter 추가 + `<Badge>` 표시 + ✕ remove)
  - UV/AC는 `<Select>` (enum 옵션 하드코딩 — REQUIRED/PREFERRED/DISCOURAGED, NONE/INDIRECT/DIRECT/ENTERPRISE)
  - 저장 직전 diff 모달 (현재 값 → 새 값) — 변경 항목만 강조
  - PUT 성공 → invalidate + 토스트

### M2-T3. AAGUID Policy (1일)

- `src/pages/tenant/AttestationPolicyTab.tsx`:
  - mode select + UUID chip input (zod로 UUID format 검증)
  - mdsStrict 토글 — on 변경 시 경고 ("MDS 서버 비활성이면 strict tenant는 등록 차단됨" 안내)
  - PUT → invalidate

### M2-T4. 빈 상태 / 에러 / 권한 처리 (0.5일)

- 403 (M002) → "이 tenant에 대한 권한이 없습니다" 카드 + 뒤로가기
- 404 (T001) → tenant not found 페이지

### M2 종료 게이트

- [ ] F-1 e2e 시나리오 통과 (PLATFORM_OPERATOR 신규 tenant → webauthn → policy 저장)
- [ ] 잘못된 slug 형식 → 즉시 클라이언트 에러
- [ ] RP_ADMIN이 다른 tenant 페이지 접근 시도 → 권한 페이지

---

## M3 — API Key + Credentials (D12–D15)

### M3-T1. API Key 목록 + 발급 + 회수 (2일)

- `src/pages/tenant/ApiKeysTab.tsx`:
  - `useQuery(['apiKeys', tenantId])` → `List<ApiKeyView>`
  - shadcn `<Table>` — prefix, name, status, createdAt, actions
  - 회수된 행은 `text-muted-foreground` + opacity 70
- 신규 발급 모달:
  - name 입력 + 검증 (max 100, `^[\x20-\x7E]+$`)
  - submit → `POST` → 응답의 `plaintext`를 별도 상태에 저장
  - **성공 시 발급 모달을 닫지 않고 plaintext 노출 모달로 전환** (PRD §6.3 와이어프레임)
- IssuedKey 노출 모달 (`<Dialog>` controlled, esc/외부 클릭 차단):
  - plaintext + 복사 버튼 (`navigator.clipboard.writeText`)
  - 체크박스: "안전한 곳에 복사했습니다" (state, default unchecked)
  - 닫기 버튼은 체크박스 체크 후에만 enable
  - 닫으면 state에서 plaintext 즉시 wipe (메모리 cleanup)
- 회수:
  - 확인 다이얼로그 (prefix + name 표시)
  - DELETE → mutation → invalidate
  - 회수 → 서버가 audit 기록 + Redis pub/sub로 다른 instance cache evict (자동, 별 처리 불필요)

### M3-T2. Credentials 목록 + 검색 + revoke (2일)

- `src/pages/tenant/CredentialsTab.tsx`:
  - `useQuery(['credentials', tenantId, page, size], ...)` → `PageResponse<CredentialView>`
  - 컬럼: credentialId(`…마지막12자` ellipsis), externalUserId, nickname, status, aaguid(`<Badge>`), transports, signatureCounter, lastUsedAt, createdAt
  - 검색 box (externalUserId substring):
    - **v1.0**: client-side filter (전체 페이지 fetch 후 frontend filter — 성능 한계 명확히)
    - **v1.1**: 서버에 `?externalUserId=` 추가 (PRD §7 참조)
- 회수 다이얼로그:
  - credentialId 마지막 12자 표시
  - DELETE → invalidate

### M3 종료 게이트

- [ ] F-2 (API key rotation) e2e
- [ ] F-3 (credential revoke) e2e
- [ ] plaintext 모달 닫기 후 plaintext가 React DevTools / DOM에 남지 않음 (수동 검증)
- [ ] 회수 후 즉시 다시 발급 → 발급 정상 동작

---

## M4 — Audit + Funnel (D16–D18)

### M4-T1. Audit log 목록 (1일)

- `src/pages/tenant/AuditTab.tsx`:
  - `useQuery(['audit', tenantId, page, size])`
  - 컬럼: createdAt(format), eventType `<Badge>` (색상 매핑), actorType, actorId(`…8`), subjectType, subjectId(`…8`), payload(JSON preview — 첫 80자 + …)
  - payload 클릭 → 모달에서 pretty-printed JSON
- eventType 필터 (client-side, v1.0):
  - `<Select multi>` — TENANT_CREATED, API_KEY_*, CREDENTIAL_*, SIGNATURE_COUNTER_REGRESSION, ATTESTATION_TRUST_FAILED

### M4-T2. Hash chain Verify (1일)

- 상단 카드: "Hash chain 검증" 버튼 + 날짜 범위 picker (기본 from=어제 0시, to=현재 — UTC)
- 실행 → `GET /audit-logs/verify?from=&to=` (ISO_DATE_TIME 형식)
- 결과 표시:
  - intact=true: `<Badge variant="success">무결</Badge>` + verifiedRows N건
  - intact=false: `<Badge variant="destructive">위변조 N건</Badge>` + tamperedEntryIds 목록 + audit log 목록에서 해당 행 하이라이트 (URL param `?highlight=...`)
- 결과를 page에 inline 카드로 유지 (페이지 떠나면 사라짐)

### M4-T3. Funnel 카드 (0.5일)

- `src/pages/tenant/FunnelTab.tsx`:
  - `useQuery(['funnel', tenantId, windowDays])`
  - 카드 4개: 등록 시도/성공/전환율, 인증 시도/성공/전환율
  - windowDays select (1 / 7 / 30)

### M4-T4. 빈 상태 / 에러 (0.5일)

- audit log 비어있음 → "아직 활동이 없습니다" empty state
- verify 결과가 0 rows → "선택한 기간에 audit 행이 없습니다" 안내

### M4 종료 게이트

- [ ] F-4 (월간 보고서) e2e — 검증 결과 카드를 콘솔에서 직접 확인 후 화면 캡처로 보고서 발급 가능
- [ ] payload preview 클릭 → 전체 JSON 표시
- [ ] eventType 필터 → 클라이언트 즉시 반영

---

## M5 — Polishing + Deploy (D19–D21)

### M5-T1. UX 마감 (1일)

- 한국어 카피 일관성 검토 (CTA: "저장" vs "변경", "회수" vs "삭제")
- 에러 메시지 매핑 테이블 (ErrorCode → 사용자 친화 메시지)
- 로딩 스피너 / skeleton (shadcn `<Skeleton>`)
- 빈 상태 일러스트 (단순 SVG, self-host)
- 키보드 단축키: `Cmd/Ctrl+K`로 빠른 tenant 검색 (PLATFORM_OPERATOR) — v1.1로 미룰 수도 있음

### M5-T2. 접근성 + Lighthouse (0.5일)

- axe-core 통합 (Playwright + axe)
- color contrast AA 통과
- 모든 mutation 버튼 focus 상태 명확 (Tailwind `focus:ring-2`)
- Lighthouse:
  - Performance ≥ 80 — lazy chunk + image optim
  - Accessibility ≥ 90
  - Best Practices ≥ 85

### M5-T3. e2e 시나리오 자동화 (0.5일)

`tests/e2e/`:
- `auth.spec.ts` — 로그인/로그아웃/401 자동 로그아웃
- `tenant-onboarding.spec.ts` — F-1
- `api-key-rotation.spec.ts` — F-2 (plaintext 모달 닫기 강제 포함)
- `credential-revoke.spec.ts` — F-3
- `audit-verify.spec.ts` — F-4

Playwright fixture로 admin 계정 시드 (테스트 DB에 SQL로 PLATFORM_OPERATOR + RP_ADMIN 1개씩 사전 생성). 테스트는 docker-compose로 서버+postgres+redis 띄우고 실행.

### M5-T4. 배포 runbook (0.5일)

`admin-console-docs/deployment.md`:
- 빌드: `docker build --build-arg VITE_API_BASE_URL=https://api.passkey.example.com -t passkey-admin-console:v1.0 .`
- k8s manifest 또는 docker-compose stanza:
  - `passkey-admin-console` 서비스 (nginx, 1 replica)
  - ingress: `admin.passkey.example.com` → 80 with TLS termination
- env 변수: 없음 (build-time만)
- 헬스체크: `GET /healthz` → 200
- 롤백: 이전 이미지 태그로 deployment 교체

### M5-T5. 최종 게이트 (0.5일)

- [ ] 모든 P0 REQ 구현 + 체크리스트 통과
- [ ] e2e 5종 CI에서 그린
- [ ] Lighthouse 기준 통과
- [ ] `architecture.md §11`에 admin console v1.0 항목 추가 ("2026-06-XX | Admin Console v1.0 | Vite/React SPA, 4 role 매트릭스, 5 핵심 user flow, 별도 도메인 + CORS/SameSite=None")
- [ ] `admin-console-docs/deployment.md` 최종본
- [ ] 운영자 1명 대상으로 demo (F-1 ~ F-4) 후 피드백 1회 반영

---

## 의존성 / 블로커 / 위험

### 의존성 그래프

```
M0-T3 (서버 CORS) ──┬─→ M1 전체
                    └─→ 모든 M2~M4 mutation
M1-T1 (api 클라이언트) ──→ M1-T3 (login) ──→ M1-T4 (layout) ──→ M2~M4
M1-T4 (layout) ──→ M2/M3/M4 (모두 layout 안에서 동작)
M2-T1 (tenant 상세 골격) ──→ M2-T2, M2-T3, M3, M4 (모두 tenant detail 탭으로 진입)
```

### Blocker 리스크

| 항목 | 가능성 | 대응 |
|------|--------|------|
| M0-T3 서버 PR 머지 지연 | 중 | M0-T3가 시작 1일 전에 PR 올리기. 그 사이 M0-T1/T2 진행 가능 |
| 별도 도메인 vs 같은 etld+1 도메인 정책 미정 | 중 | M0 시작 전에 운영팀 합의. 미합의 시 임시로 `*.passkey.example.com` 사용 가정 |
| Playwright 환경 (docker-compose 서버+DB) flaky | 저 | 초기에는 unit test 위주, e2e는 M5에서 안정화 |
| shadcn copy-paste 컴포넌트 + 디자인 토큰 불일치 | 저 | M1-T4에서 토큰을 먼저 픽스 (color/spacing/radius) |

---

## 변경 관리 / 협업 규칙

- 본 admin console 작업은 `admin-console/` 디렉터리에서 (서버와 별도 PR 트랙)
- 서버 PR (M0-T3, REQ-C-2/REQ-D-2 v1.1 등)은 `server/` 디렉터리만 건드림
- 커밋 컨벤션: `[admin]` prefix (예: `[admin] M2-T1: tenant list page`)
- PR 라벨: `admin-console`, `backend-needs-change`
- 일일 standup용 진척표: M0–M5 각 task에 `[ ]/[x]` 토글

---

## v1.1 이후 (참고)

| 항목 | 메모 |
|------|------|
| AdminUser CRUD | 운영자 self-service 추가, password 재설정 |
| 서버 audit eventType 필터 | `?eventType=` query 추가 |
| 서버 credential externalUserId 필터 | `?externalUserId=` query |
| Verify 결과 PDF/PNG export | jsPDF 통합 |
| AAGUID → 제조사 이름 매핑 | MDS BLOB 기반 (`/_diag/mds-status` 활용) |
| 시계열 chart (funnel) | recharts |
| Sentry / 텔레메트리 | error monitoring |
| EN i18n | i18next 통합 |
| SSO / OIDC | v2 |

---

## 참고 자료

- [PRD](./admin-console-prd.md)
- 백엔드 architecture: `../docs/architecture.md`
- 에러 코드: `../docs/error-codes.md`
- SDK 패턴 참고: `../sdk/src/PasskeyClient.ts` (envelope unwrap 처리)
- 배포 토대: `../docs/deployment.md`
