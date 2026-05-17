# Passkey Admin Console — Deployment

> [PRD](./admin-console-prd.md) §5.3, [action plan](./admin-console-action-plan.md) M5-T4의 정본.
> 운영자가 admin SPA를 배포 / 롤백 / 디버그할 때 보는 단일 문서.

## 1. 산출물

`admin/` 디렉터리에서 빌드되며, 최종 산출물은 **단일 nginx 컨테이너**:

```
admin/dist/                      ← vite build 결과 (HTML/JS/CSS)
admin/Dockerfile                 ← multi-stage: node:20-alpine → nginx:alpine
admin/nginx.conf                 ← SPA fallback + 보안 헤더 + /healthz
```

빌드 산출물에 **시크릿이 들어가지 않습니다**. Vite는 `VITE_*` env만 번들에 박는데, 그 값은 모두 공개 가능한 항목(API base URL)입니다.

## 2. 빌드

### 2.1 로컬 (Mac/Linux)

```bash
cd admin
npm ci
VITE_API_BASE_URL=https://api.passkey.example.com npm run build
ls -la dist/
```

`dist/index.html` 한 페이지 + 자산. 총 gzipped ≈ 185 KB (lazy chunk 9종).

### 2.2 Docker 이미지

```bash
docker build \
  --build-arg VITE_API_BASE_URL=https://api.passkey.example.com \
  -t passkey-admin-console:0.1.0 \
  admin/

docker run --rm -p 8081:80 passkey-admin-console:0.1.0
# → http://localhost:8081
# → http://localhost:8081/healthz  (200 ok)
```

이미지 크기: ~30 MB (nginx:alpine base).

### 2.3 다중 환경

`VITE_API_BASE_URL`을 환경별로 분리:

| 환경 | `VITE_API_BASE_URL` |
|------|---------------------|
| dev (로컬) | `''` (Vite proxy로 same-origin) |
| staging | `https://api.stg.passkey.example.com` |
| prod | `https://api.passkey.example.com` |

각 환경마다 별도 태그로 이미지를 빌드합니다 (`:0.1.0-stg`, `:0.1.0`).

## 3. 인프라

### 3.1 k8s manifest (예시)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: passkey-admin-console
  namespace: passkey
spec:
  replicas: 1
  selector: { matchLabels: { app: passkey-admin-console } }
  template:
    metadata: { labels: { app: passkey-admin-console } }
    spec:
      containers:
        - name: web
          image: passkey-admin-console:0.1.0
          ports: [{ containerPort: 80 }]
          readinessProbe:
            httpGet: { path: /healthz, port: 80 }
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /healthz, port: 80 }
            periodSeconds: 30
          resources:
            requests: { cpu: 25m, memory: 32Mi }
            limits:   { cpu: 200m, memory: 128Mi }
---
apiVersion: v1
kind: Service
metadata: { name: passkey-admin-console, namespace: passkey }
spec:
  selector: { app: passkey-admin-console }
  ports: [{ port: 80, targetPort: 80 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: passkey-admin-console
  namespace: passkey
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts: [admin.passkey.example.com]
      secretName: admin-passkey-tls
  rules:
    - host: admin.passkey.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: passkey-admin-console
                port: { number: 80 }
```

### 3.2 docker-compose stanza (단일 호스트 배포)

```yaml
services:
  admin-console:
    image: passkey-admin-console:0.1.0
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1/healthz"]
      interval: 30s
      timeout: 3s
      retries: 3
    networks: [edge]
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.admin.rule=Host(`admin.passkey.example.com`)"
      - "traefik.http.routers.admin.tls.certresolver=le"
      - "traefik.http.services.admin.loadbalancer.server.port=80"
```

## 4. 백엔드 호환 환경변수 (반드시 함께 설정)

admin console이 별도 도메인이면 서버에서 다음 env를 prod에 설정:

| env | 값 | 효과 |
|-----|----|------|
| `PASSKEY_ADMIN_CONSOLE_ORIGIN` | `https://admin.passkey.example.com` | `AdminSecurityConfig`의 CORS allowlist + credentials 활성화 |
| `PASSKEY_COOKIE_SAME_SITE` | `None` | CSRF 쿠키를 cross-site로 전송 (Secure=true와 묶임) |
| `PASSKEY_SESSION_SAME_SITE` | `none` | Spring Session 쿠키도 cross-site |
| `PASSKEY_COOKIE_SECURE` | `true` | SameSite=None은 Secure 필수 |
| `PASSKEY_HIKARI_POOL_MAX` | `20` | Hikari 풀 크기 (기본) |

대안: 같은 etld+1(`*.passkey.example.com`) 도메인 정책이라면 `*_SAME_SITE`는 `lax`/`Lax` 유지 가능 — 운영팀과 합의 후 결정 (PRD §10 위험 §1·2).

검증 — preflight curl:
```bash
curl -i -X OPTIONS \
  -H "Origin: https://admin.passkey.example.com" \
  -H "Access-Control-Request-Method: POST" \
  https://api.passkey.example.com/api/v1/admin/auth/login
# 응답에 다음이 있어야 함:
#   Access-Control-Allow-Origin: https://admin.passkey.example.com
#   Access-Control-Allow-Credentials: true
#   Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
```

## 5. 보안 헤더 (nginx)

`admin/nginx.conf`가 다음 헤더를 모든 응답에 자동 추가:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy: default-src 'self'; connect-src 'self' https://api.passkey.example.com; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self';`

⚠️ **CSP `connect-src`** 의 API 도메인은 실제 운영 도메인으로 갈아 끼워야 합니다. staging 등 다른 도메인을 쓰면 SPA가 API를 호출하지 못합니다.

## 6. 운영 체크리스트 (배포 직후)

1. **healthcheck**: `curl -fsS https://admin.passkey.example.com/healthz` → `ok`.
2. **SPA fallback**: `curl -fsS https://admin.passkey.example.com/tenants` → `200` + HTML (index.html이 반환되어야 함, 404 아님).
3. **자산 캐싱**: `curl -I https://admin.passkey.example.com/assets/index-*.js` → `Cache-Control: public, immutable`.
4. **CSP 헤더**: 위 `Strict-Transport-Security` + `Content-Security-Policy` 헤더 존재.
5. **CORS 동작**: 위 §4 preflight curl.
6. **로그인 흐름**: 시드된 PLATFORM_OPERATOR 계정으로 로그인 → `/tenants` 자동 이동.
7. **plaintext 모달**: 신규 tenant에 API key 발급 → plaintext 모달 표시 → 체크박스 강제 → 닫은 후 React DevTools에서 plaintext 잔존 없음 (수동).
8. **Hash chain verify**: 임의 tenant의 audit log 탭 → "검증 실행" → `intact` 배지.

## 7. 롤백 절차

이미지 태그 단위 immutable 배포 — 이전 태그를 다시 지정.

### k8s
```bash
kubectl -n passkey set image deploy/passkey-admin-console \
  web=passkey-admin-console:0.1.0-previous
kubectl -n passkey rollout status deploy/passkey-admin-console
```

### docker-compose
```bash
docker compose -f docker-compose.prod.yml \
  pull admin-console && docker compose up -d admin-console
```
(`docker-compose.prod.yml`의 `image:` 태그를 이전 버전으로 수정 후)

서버는 건드릴 필요 없음 — admin 콘솔만 독립적으로 롤백 가능합니다.

## 8. 트러블슈팅

| 증상 | 원인 후보 | 확인 |
|------|-----------|------|
| 로그인 후 즉시 401 | CORS allowlist에 console origin 누락 | server preflight curl §4 |
| 쿠키가 안 들어옴 | SameSite=None인데 Secure=false / HTTP 환경 | 브라우저 DevTools Application → Cookies → `PASSKEY_SESSION` row 확인 |
| `XSRF-TOKEN` 누락 | 쿠키 Path 설정 오류 | server `passkey.cookie.same-site=None`이면 path가 자동으로 `/` 처리됨 (`AdminSecurityConfig`) |
| API 호출 시 mixed content | CSP `connect-src`가 http일 때 https API 차단 | `nginx.conf` CSP 헤더의 `connect-src` 검토 |
| `/tenants` 새로고침 시 nginx 404 | SPA fallback 누락 | `nginx.conf`의 `try_files $uri /index.html;` 라인 확인 |
| login 했는데 항상 RP_ADMIN으로 라우팅 | `/me`의 `tenantId`가 NULL이어야 PLATFORM_OPERATOR | DB `admin_user.tenant_id` 확인 |

## 9. 관찰성 (v1.1 후속)

현재 admin console은 브라우저 console 로그만 사용 (NFR-O-4). v1.1에서 Sentry / OpenTelemetry web SDK 추가 검토.

## 10. 의존성 그래프 (요약)

```
admin (Vite SPA, nginx)
   │
   │ CORS + 쿠키 + REST
   ▼
api.passkey.example.com  ──→ passkey-server (Spring Boot)
                                  │
                                  ├─→ postgres (RLS)
                                  └─→ redis (session + rate-limit + pub/sub)
```

admin/SPA는 백엔드와 완전 분리 — 빌드/롤백/스케일링 모두 독립.
