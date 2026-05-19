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
   │ Oracle 19c       │  │ Oracle reader  │
   │ (Data Guard)     │  │  (optional)    │
   └──────────────────┘  └────────────────┘

   ┌─────────────────┐
   │ Redis Sentinel  │   ← challenge + rate-limit. SPOF 회피 필수.
   └─────────────────┘
```

## DB 사용자 3-tier (Oracle 19c)

PG의 `BYPASSRLS` 역할 속성은 Oracle에서는 `EXEMPT ACCESS POLICY` 시스템 권한으로 대체됩니다.

| 사용자 | 권한 | 용도 |
|--------|------|------|
| `APP_MIGRATOR` | 모든 객체 owner. `CREATE USER`, `CREATE PUBLIC SYNONYM`, `EXECUTE ON SYS.DBMS_RLS / DBMS_LOCK / DBMS_SESSION` (WITH GRANT OPTION) | Flyway 마이그레이션 + VPD 정책 부착 전용. 운영에서는 슈퍼유저 권한 회수. |
| `APP_RUNTIME` | 객체별 DML grant. `EXEMPT ACCESS POLICY` **미부여** | RP API 트래픽 + RP Admin 트래픽. VPD 적용 → 컨텍스트 미설정 시 0 rows. |
| `APP_ADMIN` | 객체별 DML grant. `EXEMPT ACCESS POLICY` **부여** | Platform Operator 트래픽 (cross-tenant 조회). `PASSKEY_ADMIN_ENABLED=true`일 때만 활성. |

## 환경 변수

| Variable | Required | Description |
|----------|----------|-------------|
| `SPRING_PROFILES_ACTIVE` | yes | 운영은 `prod` |
| `SPRING_DATASOURCE_URL` | yes | `jdbc:oracle:thin:@//host:1521/SERVICE_NAME` (PDB service name for Cloud DB / RDS) |
| `SPRING_DATASOURCE_USERNAME` | yes | `APP_RUNTIME` |
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

### 🔴 배포 차단 (없으면 부팅 실패 또는 보안 사고)

- [ ] **`PASSKEY_JWT_SECRET`** — 최소 32바이트 (HMAC-SHA256 키). secret manager (k8s Secret / Vault) 주입. 누락 시 startup fail.
- [ ] **`PASSKEY_ADMIN_CONSOLE_ORIGIN`** — admin SPA가 백엔드와 다른 origin이면 필수 (예: `https://admin.passkey.example.com`). 누락 시 CORS pre-flight 실패 → 모든 admin API 호출 차단.
- [ ] **`PASSKEY_MDS_ROOT_CA`** — `/etc/passkey/fido/Global_Sign_Root_CA.pem`에 FIDO Alliance Global Root CA PEM 마운트 (k8s Secret 권장). MDS 기본 ON이라 누락 시 strict tenant의 신규 등록이 `MDS_UNAVAILABLE`로 실패.
- [ ] **`PASSKEY_ACTUATOR_PASSWORD`** — `/actuator/**` Basic auth. 누락 시 startup fail.
- [ ] **DB 비밀번호 4종** — `PASSKEY_DB_MIGRATOR_PASSWORD`, `PASSKEY_DB_RUNTIME_PASSWORD`, `PASSKEY_DB_ADMIN_PASSWORD`, Flyway placeholder (V1__baseline.sql이 참조).
- [ ] **`PASSKEY_REDIS_HOST` / `PASSKEY_REDIS_PASSWORD`** — Spring Session + rate limit + challenge store.

### 🟠 보안 권장

- [ ] **쿠키 Secure 플래그** — `PASSKEY_COOKIE_SECURE=true` (prod 기본값). HTTP 종단점 절대 금지.
- [ ] **`PASSKEY_COOKIE_SAME_SITE=None`** — admin SPA가 cross-site domain일 때. 이 경우 Secure도 자동 필수.
- [ ] **`/_diag/**`은 LB/네트워크 레이어에서 차단** — 이중 방어. `mds-status`, `rate-limit-status`, `mds-refresh` 등.
- [ ] **`/actuator/prometheus` 외부 노출 금지** — k8s NetworkPolicy 또는 LB rule로 내부 Prometheus만 접근.
- [ ] **`app_migrator`는 마이그레이션 실행 시에만** — 평시 슈퍼유저 권한 회수.
- [ ] **TLS 종단** — LB에서 TLS termination, app은 HTTP. HSTS 헤더는 코드가 자동 발행 (`Strict-Transport-Security: max-age=31536000`).

### 🟡 성능 / 안정 권장

- [ ] **`PASSKEY_HIKARI_POOL_MAX=40`** (기본 20) — 1k req/s 트래픽 대비. 시뮬레이션 후 조정.
- [ ] **Argon2id 파라미터** (`PASSKEY_API_KEY_ARGON2_*`) — 기본값 memory=64MB / iterations=2. 실서버 CPU 프로파일링 후 결정.
- [ ] **`audit_log` 미래 월 partition 사전 생성** — 운영 cron으로 매월 말일 다음 달 partition 생성 (V7 헤더 참고).
- [ ] **MDS BLOB 갱신 모니터링** — `passkey_system_mds_refresh{result}` Prometheus counter. result=fail이 누적되면 alert.
- [ ] **Audit hash chain 일일 검증 결과** — `AuditChainScheduler`가 00:30 UTC에 verify. 실패 시 ERROR 로그 + counter 증가 → alert.
- [ ] **Backup: Postgres PITR** — audit_log는 컴플라이언스 자료이므로 retention 정책 별도 (최소 1년 권장). Redis는 ephemeral이라 backup 불필요.
- [ ] **Flyway 새 마이그레이션 시 staging에서 먼저 적용**.

### 🟢 부트스트랩 1회성

- [ ] **첫 PLATFORM_OPERATOR admin** — DB에 직접 SQL insert (위 "첫 admin 만들기" 섹션 참고). 로그인 후 즉시 비밀번호 변경 다이얼로그로 교체.
- [ ] **첫 tenant 생성** — admin SPA `/tenants` → "신규 tenant".
- [ ] **첫 tenant의 WebAuthn config** — rpId, origins, UV, AttestationConveyance, ResidentKey, CredProtect 설정.
- [ ] **첫 RP API key 발급** — 발급 직후 1회만 plaintext 노출 → RP 백엔드의 secret manager에 즉시 저장.

## 환경 변수 빠른 참조

| 변수 | 기본값 | 비고 |
|---|---|---|
| `PASSKEY_JWT_SECRET` | (필수) | 32바이트+ HMAC-SHA256 키 |
| `PASSKEY_JWT_SECRET_PREVIOUS` | "" | 시크릿 교체 중인 동안만 설정 (이전 시크릿) |
| `PASSKEY_ADMIN_CONSOLE_ORIGIN` | "" | cross-site admin 호스팅 시 필수 |
| `PASSKEY_MDS_ENABLED` | `true` | air-gapped 환경이면 `false` |
| `PASSKEY_MDS_ROOT_CA` | `file:/etc/passkey/fido/Global_Sign_Root_CA.pem` | MDS=true면 필수 |
| `PASSKEY_MDS_BLOB_URL` | `https://mds3.fidoalliance.org/` | private mirror 시 변경 |
| `PASSKEY_MDS_REFRESH_CRON` | `0 0 4 * * *` | 매일 04:00 (서버 시각) |
| `PASSKEY_COOKIE_SECURE` | `true` | HTTP dev에서만 false |
| `PASSKEY_COOKIE_SAME_SITE` | `Lax` | cross-site면 `None` |
| `PASSKEY_HIKARI_POOL_MAX` | `20` | 트래픽에 맞춰 조정 |
| `PASSKEY_RL_REGISTRATION` / `_AUTHENTICATION` / `_DEFAULT` / `_ADMIN_LOGIN` | 30/60/120/5 | per minute |
| `PASSKEY_ACTUATOR_USER` / `_PASSWORD` | actuator / (필수) | `/actuator/**` Basic auth |
| `PASSKEY_REDIS_HOST` / `_PORT` / `_PASSWORD` | localhost / 6379 / (필수) | Spring Session + rate limit |

## JWT 시크릿 로테이션

운영 중 시크릿 교체는 반드시 **두 단계 롤링 재시작**으로 진행합니다. 한 단계로 통합하면 rolling restart 도중 인스턴스 A(새 시크릿)와 인스턴스 B(구 시크릿)가 공존하는 수십 초~수 분 동안 — 한쪽 인스턴스에서 발급된 토큰을 다른 인스턴스가 거부하여 `A004 INVALID_TOKEN` 폭증이 발생합니다.

### Phase 1 — "verify dual, sign old" (1~24시간 유지)

신/구 두 시크릿을 **모두 verify 가능**하게 만들되, **발급(sign)은 여전히 구 시크릿**으로 합니다. 이 단계는 verify 측면만 무중단으로 확장하는 것이 목적입니다.

> 현재 `TokenService`는 `secret`을 sign + verify primary로, `previous-secret`을 verify-only fallback으로 사용합니다. Phase 1에서 sign을 강제로 구 시크릿에 고정하려면 새 시크릿을 `previous-secret`에 넣고 구 시크릿을 `secret`으로 유지하세요. **모든 인스턴스가 dual-verify 상태**가 될 때까지 (rolling restart 완료) 기다립니다 — 보통 1~5분.

1. 새 32바이트+ 시크릿 생성: `openssl rand -base64 48`
2. 환경변수 갱신:
   - `PASSKEY_JWT_SECRET = <기존 값>` (그대로)
   - `PASSKEY_JWT_SECRET_PREVIOUS = <새 값>`
3. 롤링 재시작. 모든 인스턴스가 dual-verify 상태가 될 때까지 대기.

### Phase 2 — "sign new, verify dual" (refresh-ttl 윈도우 유지: 기본 30일)

이제 sign을 새 시크릿으로 swap합니다.

1. 환경변수 갱신:
   - `PASSKEY_JWT_SECRET = <새 값>`
   - `PASSKEY_JWT_SECRET_PREVIOUS = <구 값>`
2. 롤링 재시작. 이 시점부터 모든 신규 발급은 새 시크릿 서명, 구 시크릿 발급분은 verify-only로 살아남음.
3. **최소 `refreshTtlSeconds`(기본 30일) 이상 유지**. SOP 권장값은 30일 + 24시간 안전마진.

### Phase 3 — 구 시크릿 회수

1. 환경변수 갱신:
   - `PASSKEY_JWT_SECRET_PREVIOUS = ""` (비움)
2. 롤링 재시작.
3. 시크릿 매니저에서 구 시크릿 영구 폐기.

### 비상 회전 (Compromised key)

키 노출이 의심되면 Phase 1을 **건너뛰고** Phase 2부터 즉시 실행하되, **사용자 강제 재로그인**을 수용합니다:

- `PASSKEY_JWT_SECRET = <새 값>`, `PASSKEY_JWT_SECRET_PREVIOUS = ""`
- 모든 outstanding access/refresh 토큰이 `A004 INVALID_TOKEN`/`A011 REFRESH_TOKEN_REVOKED`로 거부됨.
- RP 클라이언트가 자동으로 재로그인 플로우로 진입.

비상 회전 시 `refresh_token` 테이블도 함께 truncate하면 리플레이 면역이 즉시 보장됩니다 — SOP에 따라 보안팀이 승인한 경우에만.

### 모니터링

- 회전 중 `A004 INVALID_TOKEN` 메트릭 watch: Phase 1/2/3 전환 직후 5분 모니터링.
- `A004 / A011`이 baseline의 2배 이상으로 5분 지속 → 즉시 alert (Phase 1을 충분히 기다리지 않았거나 캐시된 토큰이 dual-verify 영역 밖에 있음).

## MDS3 운영 가이드

기본값 ON. 운영자는 다음을 보장해야 함:

1. **루트 CA PEM 마운트** — FIDO Alliance가 발행한 `Global Sign Root CA` PEM 파일. k8s Secret으로 만들어 `/etc/passkey/fido/Global_Sign_Root_CA.pem` 경로에 마운트.
2. **BLOB endpoint 접근** — 기본 `https://mds3.fidoalliance.org/`. 폐쇄망 환경이라면 내부 mirror 운영 후 `PASSKEY_MDS_BLOB_URL` 교체.
3. **갱신 상태 모니터링** — admin SPA `/system` 페이지 또는 `GET /api/v1/admin/system/mds/status`. `status=READY` + `lastFetched` 24h 이내 + `nextUpdate` 미래여야 정상.
4. **강제 갱신** — `POST /api/v1/admin/system/mds/refresh` (PLATFORM_OPERATOR). FIDO Alliance가 보안 사건으로 긴급 BLOB 발행하면 다음 일정 갱신을 기다리지 말고 즉시 호출.
5. **갱신 실패 대응** — stale BLOB로 계속 동작 (fail-open). 단 24h 이상 stale이면 alert 후 수동 갱신.
6. **strict 모드 활성화** — admin SPA의 tenant 상세 → AAGUID 정책 탭 → `mdsStrict` 토글. 켜기 전에 MDS status가 READY인지 확인.

## 알려진 제약 (v1)

- Conditional UI / passkey autofill 미지원 → v2.
- Native mobile SDK 미지원 → v2.
- 단일 region 가정 (RLS는 region별 멀티마스터를 지원하지 않음).
- ⌘K 명령 팔레트 SPA placeholder만 노출 → v1.4.
