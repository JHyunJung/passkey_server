# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 프로젝트 한 줄 요약

Spring Boot 3.5/Java 17 + Oracle VPD 기반 멀티테넌트 FIDO2/WebAuthn 패스키 인증 플랫폼 (RP API + Admin + JS SDK).

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
# 의존 인프라 (Oracle 19c-compatible (gvenzl/oracle-free:23-slim-faststart) + Redis 7)
docker compose up -d

# 부팅
./gradlew bootRun --args='--spring.profiles.active=local'

# 전체 검증 (slice + integration + ArchUnit + spotless)
./gradlew check

# DB schema reset (PG schema drop → Oracle 객체 drop. 자세한 스니펫은 docs/deployment.md)
docker cp server/docker/oracle-init/.. passkey-oracle:/tmp/oracle_clean.sql  # or hand-write
docker exec passkey-oracle sqlplus -L -S APP_MIGRATOR/change_me_migrator@//localhost:1521/FREEPDB1 @/tmp/oracle_clean.sql
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

**멀티테넌트 격리 = Oracle Virtual Private Database (VPD)** (v1.5에서 PG RLS → Oracle 19c로 이식). 7개 tenant-scoped 테이블에 `DBMS_RLS.ADD_POLICY` 부착. Hibernate `MultiTenantConnectionProvider`가 매 트랜잭션 시작 시 `passkey_ctx_pkg.set_tenant(?)` 호출 → secure application context `PASSKEY_CTX.TENANT_ID` 채움 → 정책 함수 `passkey_tenant_predicate`가 `tenant_id = HEXTORAW(SYS_CONTEXT(...))` 반환. 컨텍스트 미설정 → `'1 = 0'` predicate → 모든 SELECT 0 rows (fail-closed). HikariCP는 connection 반납 시 `clear_tenant`로 컨텍스트 명시 해제 — Oracle 컨텍스트는 per-session이라 누수 방지 필수.

**DB 사용자 3-tier** (V1__oracle_baseline.sql): `APP_MIGRATOR`(Flyway owner), `APP_RUNTIME`(EXEMPT ACCESS POLICY 미부여 — VPD 적용), `APP_ADMIN`(EXEMPT ACCESS POLICY 부여 — PG `BYPASSRLS` 대응, Platform Operator cross-tenant 조회).

**Spring Security 4-chain** (`AdminSecurityConfig`):
- Order 1 `/api/v1/admin/**` — 세션쿠키 (Spring Session Redis) + CSRF
- Order 2 `/api/v1/rp/**` — `ApiKeyAuthenticationFilter` (X-API-Key + Argon2id + Caffeine cache)
- Order 3 `/actuator/health|info`, `/_diag/**`, swagger — permit all
- Order 4 `/actuator/**` (나머지) — HTTP basic, `hasRole(ACTUATOR)`

**요청 흐름**: `TraceIdFilter`(HIGHEST) → `TenantResolutionFilter`(+10) → `RateLimitFilter`(+20) → Spring Security → Controller → `@Transactional` Service → JPA → Hibernate `getConnection(tenantId)`가 `passkey_ctx_pkg.set_tenant` 호출 → VPD-applied SQL. 트랜잭션 종료 후 connection 반납 시 `clear_tenant`.

**API key revoke**: `ApiKeyRevocationPublisher` (Redis pub/sub) → 모든 인스턴스의 Caffeine cache evict.

**Audit log**: 단일 테이블 (EE 라이선스 환경에서 Interval Partitioning을 후속 마이그레이션으로 부착 가능). per-tenant SHA-256 hash chain. `DBMS_LOCK.ALLOCATE_UNIQUE + DBMS_LOCK.REQUEST(X_MODE, release_on_commit=TRUE)`로 동시 ceremony chain fork 방지 — 구 `pg_advisory_xact_lock(hashtext(tenantId))`의 Oracle 등가물. Audit chain scheduler의 leader election은 `scheduler_lease` 행에 `SELECT ... FOR UPDATE NOWAIT`.

## 코드 작성 규칙 (ArchUnit이 PR마다 강제)

1. 모든 DB 접근은 `@Transactional` 안에서 (트랜잭션 밖이면 VPD 컨텍스트 미설정 → fail-closed)
2. `@RequestMapping` 경로는 `/api/v1/rp/**`, `/api/v1/admin/**`, `/_diag/**` 세 prefix만 허용
3. `common.*`은 도메인 패키지(`tenant`, `auth`, `credential`, `audit`, `admin`) import 금지
4. `TenantContextHolder` 호출은 허용 패키지만 (resolver, JPA infra, 명시된 service들 — `PackageArchitectureTest`의 Rule 2 참조)
5. RP-facing controller는 repository 직접 호출 금지 — service 경유 (admin은 예외)
6. 응답은 `ApiResponse<T>` envelope 통일. `ErrorCode`는 단일 enum + 도메인 prefix(C/A/T/P/R/D/M) + 3자리 번호

## 새 tenant-scoped 테이블 추가 시

1. `V<n>__create_<table>.sql` — `tenant_id RAW(16)` 컬럼 + DML grant
2. `R__vpd_policies.sql`의 테이블 배열에 추가 (DBMS_RLS.ADD_POLICY가 자동 부착)
3. `RlsPolicyCatalogTest.EXPECTED_TABLES`에 테이블명 추가 (대문자)
4. JPA Entity는 `TenantScopedEntity` 상속 (`@PrePersist`가 tenant_id 자동 주입)

## DB schema reset (통합 테스트 / 마이그레이션 변경 시)

`server/docker/oracle-init/02_clean_passkey.sql`에 정리 스크립트 보관. 단순화한 형태:

```bash
docker exec passkey-oracle sqlplus -L -S APP_MIGRATOR/change_me_migrator@//localhost:1521/FREEPDB1 <<'SQL'
BEGIN
  FOR r IN (SELECT object_name FROM user_objects WHERE object_type = 'TABLE') LOOP
    EXECUTE IMMEDIATE 'DROP TABLE "' || r.object_name || '" CASCADE CONSTRAINTS PURGE';
  END LOOP;
  FOR r IN (SELECT object_name FROM user_objects WHERE object_type IN ('PACKAGE','FUNCTION')) LOOP
    EXECUTE IMMEDIATE 'DROP ' || r.object_type || ' "' || r.object_name || '"';
  END LOOP;
  EXECUTE IMMEDIATE 'DROP CONTEXT PASSKEY_CTX';
  FOR r IN (SELECT synonym_name FROM all_synonyms WHERE owner='PUBLIC' AND table_owner='APP_MIGRATOR') LOOP
    EXECUTE IMMEDIATE 'DROP PUBLIC SYNONYM "' || r.synonym_name || '"';
  END LOOP;
  EXECUTE IMMEDIATE 'DROP USER APP_RUNTIME CASCADE';
  EXECUTE IMMEDIATE 'DROP USER APP_ADMIN CASCADE';
END;
/
SQL
```

Flyway가 다음 부팅/테스트에서 `V1__oracle_baseline.sql` + `R__vpd_policies.sql` 재적용.

## OpenAPI / Swagger

부팅 후 `http://localhost:8080/v3/api-docs` (JSON), `http://localhost:8080/swagger-ui/index.html` (UI). 운영에선 LB에서 차단 권고.
