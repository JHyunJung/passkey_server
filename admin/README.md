# Passkey Admin Console

Crosscert Passkey 멀티테넌트 어드민 SPA. Vite + React + TypeScript + Tailwind + shadcn/ui + TanStack Query.

설계 문서: [`../admin-console-docs/admin-console-prd.md`](../admin-console-docs/admin-console-prd.md), [`../admin-console-docs/admin-console-action-plan.md`](../admin-console-docs/admin-console-action-plan.md).

## 빠른 시작 (local dev)

1. 사전: 백엔드(`../server`)가 `http://localhost:8080`에서 동작 (Postgres+Redis는 `../server`의 `docker compose up -d`).
2. 의존성 설치:
   ```
   npm install
   ```
3. dev 서버 기동:
   ```
   npm run dev
   ```
   `http://localhost:5173`. `/api/*` 호출은 `vite.config.ts`의 proxy를 통해 `http://localhost:8080`으로 전달되어 same-origin처럼 동작합니다.

## 스크립트

| 명령 | 설명 |
|------|------|
| `npm run dev` | Vite dev 서버 |
| `npm run build` | `tsc -b` + `vite build` → `dist/` |
| `npm run preview` | 빌드 결과 미리보기 |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | vitest (단위) |
| `npm run e2e` | Playwright (e2e) — `npm run e2e:install` 사전 1회 |

## 프로덕션 배포

```
docker build --build-arg VITE_API_BASE_URL=https://api.passkey.example.com -t passkey-admin-console:0.1.0 .
docker run --rm -p 8081:80 passkey-admin-console:0.1.0
```

nginx의 CSP `connect-src` 값을 실제 API 도메인으로 맞추려면 `nginx.conf`의 해당 라인을 함께 변경합니다.

## 디렉터리 요지

```
src/
├── lib/        api, cn, guard, format
├── hooks/      useMe, useLogout, useToast
├── layout/     AppLayout, Sidebar, Header, Breadcrumb
├── pages/      Login, TenantsList, TenantDetail (+ tenant/* tabs)
├── components/ ui/ (shadcn) + 도메인 컴포넌트
└── types/      서버 DTO 매핑
```

## 백엔드 호환 요구

별도 도메인(`admin.passkey.example.com`)에서 호출할 때 서버에 다음이 설정되어 있어야 합니다 (`../server` 측에서 이미 반영):

- `passkey.admin.console-origin` env → CORS allowlist (`PASSKEY_ADMIN_CONSOLE_ORIGIN`)
- `passkey.cookie.same-site=None` + `passkey.cookie.secure=true` (CSRF cookie)
- `server.servlet.session.cookie.same-site=none` (Spring Session cookie)

local 개발은 Vite proxy로 same-origin이라 별도 설정 불필요.
