# Deployment Guide

## 토폴로지 (권장)

```
┌─────────────────────────────────────────────────────┐
│ Public LB / CDN                                      │
│  ├ /api/v1/rp/**     ──→ app (X-API-Key 인증)        │
│  ├ /api/v1/admin/**  ──→ app (admin session 쿠키)    │
│  ├ /_diag/**         × (운영 차단 — 내부망에서만)     │
│  └ /actuator/health  ──→ app (k8s probe 전용 노출)   │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────┐    ┌──────────────┐
│ app (N대)    │    │ app (N대)    │   ← stateless. 수평 확장.
└──────┬───────┘    └──────┬───────┘
       │                   │
       ▼                   ▼
   ┌───────────────────────────┐
   │ PgBouncer (transaction)   │   ← M5+ 권장. SET LOCAL 호환 검증 필요.
   └────────────┬──────────────┘
                ▼
   ┌─────────────────┐  ┌────────────────┐
   │ Postgres primary │  │ Postgres reader│
   └──────────────────┘  └────────────────┘

   ┌─────────────────┐
   │ Redis Sentinel  │   ← challenge + rate-limit. SPOF 회피 필수.
   └─────────────────┘
```

## DB 역할 3-tier

| 역할 | 권한 | 용도 |
|------|------|------|
| `app_migrator` | owner | Flyway 마이그레이션만. 운영에서는 슈퍼유저 권한 회수. |
| `app_runtime` | NOBYPASSRLS, NOSUPERUSER | RP API 트래픽 + RP Admin 트래픽. RLS로 격리. |
| `app_admin` | BYPASSRLS, NOSUPERUSER | Platform Operator 트래픽 (cross-tenant 조회). `PASSKEY_ADMIN_ENABLED=true`일 때만 활성. |

## 환경 변수

| Variable | Required | Description |
|----------|----------|-------------|
| `SPRING_PROFILES_ACTIVE` | yes | 운영은 `prod` |
| `SPRING_DATASOURCE_URL` | yes | `jdbc:postgresql://host:5432/passkey` |
| `SPRING_DATASOURCE_USERNAME` | yes | `app_runtime` |
| `SPRING_DATASOURCE_PASSWORD` | yes | 시크릿 매니저 |
| `SPRING_FLYWAY_USER` | yes | `app_migrator` |
| `SPRING_FLYWAY_PASSWORD` | yes | 시크릿 매니저 |
| `SPRING_FLYWAY_PLACEHOLDERS_APP_RUNTIME_PASSWORD` | yes | V1 baseline에 binding |
| `SPRING_FLYWAY_PLACEHOLDERS_APP_ADMIN_PASSWORD` | yes | 동일 |
| `SPRING_DATA_REDIS_HOST` | yes | |
| `SPRING_DATA_REDIS_PORT` | no | default 6379 |
| `SPRING_DATA_REDIS_PASSWORD` | recommended | |
| `PASSKEY_JWT_SECRET` | yes | **최소 32바이트**. fail-fast로 검증됨. |
| `PASSKEY_JWT_ISSUER` | no | default `passkey-platform` |
| `PASSKEY_JWT_ACCESS_TTL` | no | seconds, default 900 |
| `PASSKEY_JWT_REFRESH_TTL` | no | seconds, default 2592000 |
| `PASSKEY_ADMIN_ENABLED` | no | `true`이면 admin DataSource 활성 |
| `PASSKEY_RATE_LIMIT_ENABLED` | no | default `true` |
| `PASSKEY_RL_REGISTRATION` | no | per-tenant per-minute, default 30 |
| `PASSKEY_RL_AUTHENTICATION` | no | default 60 |
| `PASSKEY_RL_DEFAULT` | no | default 120 |

## Docker 빌드 + 실행

```bash
cd server
docker build -t passkey-server:0.1.0 .
docker run --rm -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e SPRING_DATASOURCE_URL=... \
  ...
  passkey-server:0.1.0
```

## Health & probes

- `GET /actuator/health` → k8s liveness/readiness 모두 지원
- `GET /actuator/health/liveness`
- `GET /actuator/health/readiness`
- `GET /actuator/prometheus` → Prometheus scrape

## 첫 admin 만들기

Bootstrap admin은 직접 SQL로 삽입합니다 (콘솔이 아직 없으므로):

```sql
-- BCrypt hash for "ChangeMe!2026":
--   $2a$10$WlQUO0... (bcrypt 라이브러리로 생성)
INSERT INTO passkey.admin_user (id, tenant_id, email, password_hash, display_name, role, status, created_at, updated_at)
VALUES (gen_random_uuid(), NULL, 'ops@crosscert.local', '$2a$10$...', 'Bootstrap Operator', 'PLATFORM_OPERATOR', 'ACTIVE', now(), now());
```

이후 `/api/v1/admin/auth/login`으로 로그인 → `/api/v1/admin/tenants`로 첫 tenant 생성.

## 운영 체크리스트

- [ ] `PASSKEY_JWT_SECRET`은 최소 32바이트, secret manager로 주입
- [ ] `app_migrator`는 마이그레이션 실행 시에만 사용, 평시엔 슈퍼유저 권한 회수
- [ ] Redis에 password 설정
- [ ] `/_diag/**`은 LB/네트워크 레이어에서 차단 (코드 레벨도 `@Profile`로 막혀있지만 이중 방어)
- [ ] `/actuator/prometheus` 외부 노출 금지 (k8s NetworkPolicy 또는 LB rule)
- [ ] Flyway 새 마이그레이션 시 staging에서 먼저 적용
- [ ] `audit_log`의 미래 월 partition을 운영 cron으로 미리 생성 (V7 헤더 참고)
- [ ] Backup: Postgres PITR. Redis는 ephemeral이라 backup 불필요.

## 알려진 제약 (v1)

- MDS BLOB 통합 미적용 → AAGUID allowlist만 사용. v1.1에서 추가.
- Conditional UI / passkey autofill 미지원 → v2.
- Native mobile SDK 미지원 → v2.
- 어드민 SPA UI 미포함 → REST API만 제공, OpenAPI spec으로 빠르게 자체 구축 가능.
- 단일 region 가정.
