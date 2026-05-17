# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

| Path | 내용 |
|------|------|
| `server/` | Spring Boot 3.5 + Java 17 백엔드 (Gradle, Kotlin DSL) |
| `sdk/` | TypeScript npm 패키지 `@crosscert/passkey-sdk` (브라우저 SDK, tsup 빌드) |
| `docs/` | architecture, integration-guide, error-codes, deployment, analysis-report |
| `multi-tenant-passkey-server-prd.md`, `*-action-plan.md`, `spring-boot-api-response-template.md` | 원본 설계 문서 — 변경 시 architecture.md와 동기화 |

`docs/architecture.md`가 새 합류자/리뷰어 시작점. 큰 변경 후 §10 변경 이력 갱신.

## Commands (server/)

```bash
# 의존 인프라 (Postgres 16 + Redis 7)
docker compose up -d

# 부팅
./gradlew bootRun --args='--spring.profiles.active=local'

# 전체 검증 (slice + integration + ArchUnit + spotless)
./gradlew check

# 격리 테스트만 — DB schema reset 후 실행 권장
docker exec passkey-postgres psql -U app_migrator -d passkey \
  -c "DROP SCHEMA IF EXISTS passkey CASCADE; DROP ROLE IF EXISTS app_runtime; DROP ROLE IF EXISTS app_admin;"
./gradlew test --tests "com.crosscert.passkey.integration.*"

# 단일 테스트
./gradlew test --tests "com.crosscert.passkey.architecture.PackageArchitectureTest"

# 자동 포맷 (Google Java Format via Spotless)
./gradlew spotlessApply

# Docker 이미지 빌드
docker build -t passkey-server:0.2.0 .
```

## Commands (sdk/)

```bash
cd sdk && npm install
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/{index.js,index.cjs,index.d.ts}
```

## 아키텍처 핵심 (한 화면 요약)

**멀티테넌트 격리 = PostgreSQL Row-Level Security**. 모든 tenant-scoped 테이블은 `ENABLE + FORCE ROW LEVEL SECURITY`. Hibernate `MultiTenantConnectionProvider`가 매 트랜잭션에 `SET LOCAL app.current_tenant = ?` 발급 → RLS 정책 `tenant_id = passkey.current_tenant_id()` 적용. 컨텍스트 미설정 → 모든 SELECT 0 rows (fail-closed).

**DB 역할 3-tier** (V1__baseline.sql): `app_migrator`(Flyway), `app_runtime`(NOBYPASSRLS, RP+RP Admin 트래픽), `app_admin`(BYPASSRLS, Platform Operator).

**Spring Security 4-chain** (`AdminSecurityConfig`):
- Order 1 `/api/v1/admin/**` — 세션쿠키 (Spring Session Redis) + CSRF
- Order 2 `/api/v1/rp/**` — `ApiKeyAuthenticationFilter` (X-API-Key + Argon2id + Caffeine cache)
- Order 3 `/actuator/health|info`, `/_diag/**`, swagger — permit all
- Order 4 `/actuator/**` (나머지) — HTTP basic, `hasRole(ACTUATOR)`

**요청 흐름**: `TraceIdFilter`(HIGHEST) → `TenantResolutionFilter`(+10) → `RateLimitFilter`(+20) → Spring Security → Controller → `@Transactional` Service → JPA → Hibernate `getConnection(tenantId)` SET LOCAL → RLS-applied SQL.

**API key revoke**: `ApiKeyRevocationPublisher` (Redis pub/sub) → 모든 인스턴스의 Caffeine cache evict.

**Audit log**: month-partitioned, per-tenant SHA-256 hash chain. `pg_advisory_xact_lock(hashtext(tenantId))`로 동시 ceremony chain fork 방지.

## 코드 작성 규칙 (ArchUnit이 PR마다 강제)

1. 모든 DB 접근은 `@Transactional` 안에서 (트랜잭션 밖이면 RLS 미적용)
2. `@RequestMapping` 경로는 `/api/v1/rp/**`, `/api/v1/admin/**`, `/_diag/**` 세 prefix만 허용
3. `common.*`은 도메인 패키지(`tenant`, `auth`, `credential`, `audit`, `admin`) import 금지
4. `TenantContextHolder` 호출은 허용 패키지만 (resolver, JPA infra, 명시된 service들 — `PackageArchitectureTest`의 Rule 2 참조)
5. RP-facing controller는 repository 직접 호출 금지 — service 경유 (admin은 예외)
6. 응답은 `ApiResponse<T>` envelope 통일. `ErrorCode`는 단일 enum + 도메인 prefix(C/A/T/P/R/D/M) + 3자리 번호

## 새 tenant-scoped 테이블 추가 시

1. `V<n>__create_<table>.sql` — `tenant_id` 컬럼 + `ENABLE + FORCE ROW LEVEL SECURITY` + GRANT
2. `R__rls_policies.sql`에 정책 추가 (`USING + WITH CHECK`)
3. `RlsPolicyCatalogTest.EXPECTED_TABLES`에 테이블명 추가
4. JPA Entity는 `TenantScopedEntity` 상속 (`@PrePersist`가 tenant_id 자동 주입)

## DB schema reset (통합 테스트 / 마이그레이션 변경 시)

```bash
docker exec passkey-postgres psql -U app_migrator -d passkey \
  -c "DROP SCHEMA IF EXISTS passkey CASCADE; DROP ROLE IF EXISTS app_runtime; DROP ROLE IF EXISTS app_admin;"
```

Flyway가 다음 부팅/테스트에서 V1~V9 + R__ 재적용.

## OpenAPI / Swagger

부팅 후 `http://localhost:8080/v3/api-docs` (JSON), `http://localhost:8080/swagger-ui/index.html` (UI). 운영에선 LB에서 차단 권고.
