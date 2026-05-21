# Architecture & Entity Reference

Crosscert Passkey Server의 내부 구조 문서. **누가** 어떤 데이터를 들고 있고, **요청 하나가** 어떤 경로로 흐르는지를 한 문서에서 빠르게 파악할 수 있도록 정리했습니다.

대상 독자: 새로 합류한 백엔드 개발자, 보안 리뷰어, 인프라 담당자.

---

## 1. 시스템 개요

```
                           ┌──────────────────────────────────────┐
   브라우저(RP 프론트)  ──→ │ RP 백엔드 (API key 보유)               │ ──→  Passkey Server
                           │  · 직접 통합: JS SDK + REST 호출         │            │
                           │  · Java RP SDK starter (ceremony 프록시) │            │
                           └──────────────────────────────────────┘            ▼
   카드사 IAM 담당      ──→  Passkey Admin Console SPA  ──────────→  Passkey Server
   (RP_ADMIN)                  (`admin/`, 구현 완료)                      │
                                                                          ▼
   Crosscert 운영자     ──→  동일 콘솔, 권한만 다름      ──────────→  Oracle 19c + Redis
   (PLATFORM_OPERATOR)
```

- **단일 Spring Boot 인스턴스**(stateless, 수평 확장 가능)
- **Oracle 19c** — 모든 영속 데이터. **Virtual Private Database(VPD)**로 테넌트 격리. (v1.5에서 PostgreSQL → Oracle 19c 이식 — §11 변경 이력 2026-05-18 항목 참조. 구 PG migration history는 `server/src/main/resources/db/archive_postgres/`에 보존)
- **Redis** — WebAuthn challenge 임시 저장(TTL 5분), rate-limit 카운터(Lua atomic INCR+EXPIRE), Spring Session, API key revocation pub/sub.
- **외부 통신** — FIDO MDS3 BLOB (strict tenant 활성 시, 1일 1회 refresh). 그 외 없음.
- **RP 통합 경로 2종** — ① 브라우저 `@crosscert/passkey-sdk` + RP 백엔드가 REST 직접 호출, ② RP 백엔드가 `passkey-rp-spring-boot-starter` 적용 (ceremony 프록시 + JWKS 기반 JWT 검증). §11 변경 이력 2026-05-20 참조.

---

## 2. 패키지 구조

```
com.crosscert.passkey
├── PasskeyApplication                main(), @EnableScheduling, @EnableConfigurationProperties
│                                    ({MdsProperties, ApiKeyProperties, WebauthnCeremonyProperties})
├── common
│   ├── response                     ApiResponse, ErrorDetail, FieldError, PageResponse
│   ├── exception                    ErrorCode (단일 enum), BusinessException, GlobalExceptionHandler
│   ├── filter                       TraceIdFilter
│   └── log                          LogSanitiser (forLog: CR/LF strip + truncate, maskEmail)
├── tenant
│   ├── domain                       Tenant, TenantUser, TenantStatus
│   ├── repository                   *Repository (Spring Data JPA)
│   ├── service                      TenantQueryService
│   ├── context                      TenantContext (record), TenantContextHolder (static ThreadLocal)
│   ├── resolver                     TenantResolver(I), HeaderTenantResolver, TenantResolutionFilter
│   └── controller                   DiagnosticsController (/_diag/whoami, profile-gated)
├── credential                       — M2 WebAuthn
│   ├── domain                       Credential, TenantWebauthnConfig, TenantAttestationPolicy + enums
│   ├── api                          REST DTO (RegistrationOptionsResponse, ...)
│   ├── challenge                    ChallengeStore (Redis, GET+DEL Lua atomic),
│   │                                ChallengeRecord, CeremonyType,
│   │                                WebauthnCeremonyProperties (challengeBytes, challengeTtl)
│   ├── webauthn                     WebAuthnConfig (bean), Base64UrlCodec
│   ├── service                      RegistrationService, AuthenticationService,
│   │                                CredentialLifecycleService, TenantWebauthnConfigService
│   ├── controller                   RegistrationController, AuthenticationController,
│   │                                CredentialController
│   ├── repository                   *Repository
│   ├── metrics                      CeremonyMetrics (Micrometer counters)
│   └── metadata                     MdsProperties, MdsBlobProvider, MdsRefreshScheduler,
│                                    MdsTrustAnchorRepositoryConfig, MdsDiagController (§10)
├── auth                             — M3 Auth
│   ├── jwt                          JwtProperties (32+ bytes secret 강제), JwtConfig,
│   │                                TokenService (verifyAccess/verifyRefresh), TokenPair
│   └── apikey
│       ├── domain                   ApiKey, ApiKeyStatus
│       ├── repository               ApiKeyRepository (findAllByTenantId, findByPrefix)
│       ├── service                  ApiKeyService (issue/verify with Caffeine LoadingCache —
│       │                            single-flight stampede 방지, DUMMY_HASH timing equalisation,
│       │                            evictByApiKeyId for cache invalidation),
│       │                            ApiKeyProperties (Argon2 파라미터, prefix/secret bytes)
│       ├── resolver                 ApiKeyTenantResolver (X-API-Key 헤더, @Profile local/test/dev only)
│       ├── security                 ApiKeyAuthenticationFilter (prod 401 보장),
│       │                            ApiKeyAuthenticationToken
│       └── cache                    ApiKeyRevocationPublisher (Redis pub/sub),
│                                    ApiKeyRevocationListenerConfig (peer cache eviction)
├── ratelimit                        RateLimitProperties (registration/authentication/default/
│                                    adminLogin perMinute), RateLimiter (Redis Lua INCR+EXPIRE
│                                    atomic), RateLimitFilter (PathClass enum 1회 분류)
├── audit                            — M3 audit log + 무결성 검증
│   ├── domain                       AuditEntry (composite PK (id, created_at)), AuditEventType, ActorType
│   ├── repository                   AuditEntryRepository (findLatestForTenant,
│   │                                streamForTenantByTime — fetchSize=1000 hint)
│   └── service                      AuditService (per-tenant SHA-256 hash chain;
│                                    append / appendAfterCommit (afterCommit + @Async) /
│                                    appendAsync / verifyIntegrity → ChainVerification record),
│                                    AuditAsyncConfig (auditExecutor 풀, CallerRunsPolicy),
│                                    AuditChainScheduler (일별 03:30 UTC 자동 검증,
│                                    audit.chain.tampered Micrometer counter)
├── admin                            — M4 Admin Console backend
│   ├── domain                       AdminUser, AdminRole, AdminStatus
│   ├── repository                   AdminUserRepository
│   ├── security                     AdminPrincipal, AdminUserDetailsService,
│   │                                AdminAuthenticationSuccessHandler, JsonLoginAuthenticationFilter,
│   │                                AdminSecurityConfig (4 chains: admin Order 1 + rp Order 2 +
│   │                                public Order 3 + actuator Order 4; CSRF cookie Secure/
│   │                                SameSite=Lax/Path=/api/v1/admin; HSTS + CSP +
│   │                                frame-ancestors + Referrer-Policy 헤더), AdminMdcFilter,
│   │                                AdminAuthz, ActuatorUserConfig
│   ├── service                      AdminTenantService (paged listAll)
│   └── controller                   AdminMe/Tenant/ApiKey/WebauthnConfig/AttestationPolicy/
│                                    Credential/Audit (list + verify)/Funnel Controllers
│                                    (모두 page 또는 tenant-scoped query)
└── infrastructure
    ├── jpa
    │   ├── BaseEntity                id + createdAt + updatedAt
    │   ├── TenantScopedEntity        BaseEntity + tenant_id (@PrePersist 자동 주입)
    │   ├── JpaConfig                 placeholder
    │   └── multitenancy
    │       ├── TenantConnectionProvider          매 트랜잭션에 passkey_ctx_pkg.set_tenant 호출
    │       ├── CurrentTenantIdentifierResolverImpl  ThreadLocal → tenantId 문자열
    │       └── HibernateMultiTenancyConfig       Hibernate property 주입
    ├── datasource
    │   └── DataSourceConfig          runtimeDataSource (@Primary), adminDataSource (@Conditional)
    └── web
        └── WebFilterConfig           TraceIdFilter → TenantResolutionFilter → RateLimitFilter 순서 pin
                                      (RemoteIpValve는 Tomcat 단계에서 selectable, server.tomcat
                                      .remoteip 설정 기반)
```

### 패키지 경계 — ArchUnit 강제

`server/src/test/java/.../architecture/PackageArchitectureTest.java`가 PR마다 검증:

1. `common.*`은 도메인 패키지(`tenant`, `auth`, `credential`, `audit`, `admin`) import 금지 — 역방향 의존 차단. (`common.log.LogSanitiser`는 utility-only이므로 도메인이 common을 import하는 정방향 의존만 허용.)
2. `TenantContextHolder` 접근은 명시된 패키지에서만 (`tenant.context`, `tenant.resolver`, `tenant.controller`, `tenant.service`, `credential.service`, `credential.challenge`, `audit.service` — `AuditService.appendAsync` + `AuditChainScheduler` 포함, `ratelimit`, `admin.security`, `admin.service`, `auth.apikey.security`, `infrastructure.jpa`, `infrastructure.jpa.multitenancy`).
3. **RP-facing** controller는 repository 직접 호출 금지 — service 경유. Admin controller는 예외 (read-through 패턴).
4. `TenantConnectionProvider`는 `infrastructure.jpa.multitenancy` 외부에서 import 금지.
5. **`@RequestMapping` 경로는 `/api/v1/rp/**`, `/api/v1/admin/**`, `/_diag/**` 셋 중 하나만 허용**.

---

## 3. 엔티티 모델

### 3.1 ERD (논리)

```
┌──────────────┐
│ tenant       │ ── RLS 비대상 (모든 lookup의 시작점)
│  id (PK)     │
│  slug (UQ)   │
│  status      │
└──────┬───────┘
       │ 1
       │
       ├──→ N  tenant_user  ─── 1:N  credential ──┐
       │      (external_id)      (RLS 적용)        │
       │                                            │
       ├──→ 0..1  tenant_webauthn_config            │
       │         (rp_id, origins, timeout, UV)      │
       │                                            │
       ├──→ 0..1  tenant_attestation_policy         │
       │         (AAGUID allowlist/denylist)        │
       │                                            │
       ├──→ N  api_key                ── RLS 비대상 (prefix lookup)
       │      (prefix UQ, Argon2 hash)
       │
       ├──→ N  audit_log              ── 단일 테이블, hash chain per tenant
       │      (event_type, payload jsonb, prev_hash → row_hash)
       │
       └──→ 0..N  admin_user          ── RLS 비대상 (로그인은 컨텍스트 set 전)
              (tenant_id NULL = PLATFORM_OPERATOR)
```

### 3.2 VPD 정책 요약 (구 RLS)

| 테이블 | VPD | 정책 식 (predicate) | 비고 |
|--------|-----|---------------------|------|
| `tenant` | ❌ | — | resolver/admin이 lookup 시작점 |
| `tenant_user` | ✅ | `tenant_id = HEXTORAW(SYS_CONTEXT('PASSKEY_CTX','TENANT_ID'))` | |
| `tenant_webauthn_config` | ✅ | 동일 | |
| `tenant_attestation_policy` | ✅ | 동일 | |
| `credential` | ✅ | 동일 | |
| `audit_log` | ✅ | 동일 | EE 라이선스 시 INTERVAL Partitioning을 후속 마이그레이션으로 부착 |
| `refresh_token` | ✅ | 동일 | |
| `api_key` | ❌ | — | prefix lookup이 컨텍스트 set 전. Argon2 hash가 실제 게이트. |
| `admin_user` | ❌ | — | 로그인 lookup이 컨텍스트 set 전. application authz가 게이트. |

정책 함수 `passkey_tenant_predicate(schema, object)`는 `SYS_CONTEXT('PASSKEY_CTX', 'TENANT_ID')`를 읽어 — 값이 없으면 `'1 = 0'`을 predicate로 반환해서 **컨텍스트 미설정 시 모든 SELECT가 0 rows (fail-closed)**. 컨텍스트는 secure application context (`CREATE CONTEXT PASSKEY_CTX USING passkey_ctx_pkg`)로, 트러스트된 setter 패키지만이 쓸 수 있습니다.

DB 사용자 3-tier (PG 역할 → Oracle user로 1:1 매핑):
- `APP_MIGRATOR` — Flyway 전용 owner, 모든 객체 소유
- `APP_RUNTIME` — RP API + RP Admin 트래픽. `EXEMPT ACCESS POLICY` 미부여 — VPD 적용.
- `APP_ADMIN` — Platform Operator의 cross-tenant 조회. `EXEMPT ACCESS POLICY` 부여 — VPD 우회 (PG의 `BYPASSRLS`와 동일).

### 3.3 엔티티 상세

#### `tenant` (`com.crosscert.passkey.tenant.domain.Tenant`)

플랫폼의 가장 큰 단위. RP 회사 하나 = tenant 하나.

| 컬럼 | 타입 | 비고 |
|------|------|------|
| `id` | uuid (PK) | application 생성 |
| `name` | text | 표시명, 예: "테스트카드" |
| `slug` | text UNIQUE | URL/header-friendly, RFC1035 hostname 형식 `^[a-z][a-z0-9-]{1,62}$` |
| `status` | text CHECK | `ACTIVE`/`SUSPENDED`/`DELETED` |
| `created_at`, `updated_at` | timestamptz | |

도메인 동작: `Tenant.create(name, slug)` → ACTIVE로 생성. `suspend()`, `activate()` 메서드.

#### `tenant_user` (`tenant.domain.TenantUser`)

RP의 end user. 패스키를 등록하는 주체. RP는 `external_id` (자기 시스템의 user id)로만 식별.

| 컬럼 | 타입 | 비고 |
|------|------|------|
| `id` | uuid (PK) | |
| `tenant_id` | uuid (FK→tenant) | RLS key |
| `external_id` | text | tenant 내 unique, RP가 부여 |
| `display_name` | text | optional |

unique: `(tenant_id, external_id)`. 동일 RP 안에서만 unique.

#### `tenant_webauthn_config` (`credential.domain.TenantWebauthnConfig`)

WebAuthn ceremony 파라미터. tenant당 정확히 1개.

| 컬럼 | 타입 | 비고 |
|------|------|------|
| `rp_id` | text | 예: `card.co.kr` |
| `rp_name` | text | 표시명 |
| `origins` | text | CSV, 예: `https://app.card.co.kr,https://www.card.co.kr` |
| `timeout_ms` | int default 60000 | |
| `user_verification` | enum | `REQUIRED`/`PREFERRED`/`DISCOURAGED` |
| `attestation_conveyance` | enum | `NONE`/`INDIRECT`/`DIRECT`/`ENTERPRISE` |

도메인 동작: `originList()` → `List<String>` 분리, `TenantWebauthnConfig.create(...)` 팩토리.

#### `tenant_attestation_policy` (`credential.domain.TenantAttestationPolicy`)

어떤 인증기(AAGUID)를 허용/거부할지. tenant당 0~1개. 없으면 permissive(`ANY`)로 자동 생성.

| 컬럼 | 타입 |
|------|------|
| `mode` | `ANY`/`ALLOWLIST`/`DENYLIST` |
| `allowed_aaguids` | CSV |
| `denied_aaguids` | CSV |

도메인 동작: `accepts(UUID aaguid)` → 모드에 따라 boolean. v1.1에서 MDS BLOB 신뢰성 검증 추가 예정.

#### `credential` (`credential.domain.Credential`)

실제 패스키. tenant_user 1명당 N개 가능 (multi-credential).

| 컬럼 | 타입 | 의미 |
|------|------|------|
| `tenant_user_id` | uuid | 어느 사용자의 것인지 |
| `credential_id` | text | base64url-encoded raw credential ID |
| `public_key_cose` | bytea | **AttestedCredentialData 전체** (AAGUID + credentialId + COSE key). webauthn4j `AttestedCredentialDataConverter`로 직렬화 |
| `aaguid` | uuid | 인증기 모델 식별자 |
| `transports` | text | CSV, 예: `internal,hybrid` |
| `user_handle` | text | base64url-encoded |
| `signature_counter` | bigint | 클론 감지용. **단조 증가만 허용** |
| `backup_eligible`, `backup_state` | boolean | passkey sync 가능/sync된 상태 |
| `nickname` | text | 사용자가 붙이는 이름 (예: "iPhone 15") |
| `status` | enum | `ACTIVE`/`REVOKED` (soft delete) |
| `last_used_at` | timestamptz | |

unique: `(tenant_id, credential_id)`. tenant 간에는 credential_id가 같아도 별개로 취급.

**핵심 도메인 메서드**: `updateSignatureCounter(long newCounter)` — `newCounter <= storedCounter` (단 둘 다 0인 경우 제외)면 `SIGNATURE_COUNTER_REGRESSION` 예외. 이게 FIDO2 clone detection의 정석.

#### `api_key` (`auth.apikey.domain.ApiKey`) — RLS 비대상

RP가 자기 서비스에서 platform API 호출할 때 쓰는 키.

| 컬럼 | 의미 |
|------|------|
| `tenant_id` | 이 키가 가리키는 tenant |
| `prefix` | unique, lookup용 8바이트 base64url (예: `aB3xY7Q9`) |
| `secret_hash` | Argon2id hash |
| `name` | 표시명, 예: "production" |
| `status` | `ACTIVE`/`REVOKED` |

발급 시 plaintext 형식: `pk_<prefix>.<secret>`. **plaintext는 발급 직후 한 번만 응답**, 이후 보존되지 않음.

#### `audit_log` (`audit.domain.AuditEntry`) — 단일 테이블 + hash chain

단일 테이블(EE 환경에서 Interval Partitioning을 후속 마이그레이션으로 부착 가능). composite PK `(id, created_at)` — partitioning 시 partition key 포함 요구사항 대비.

| 컬럼 | 의미 |
|------|------|
| `id` | uuid |
| `tenant_id` | RLS key |
| `event_type` | enum: TENANT_CREATED, API_KEY_ISSUED/REVOKED, CREDENTIAL_REGISTERED/AUTHENTICATED/REVOKED/RENAMED, SIGNATURE_COUNTER_REGRESSION, ATTESTATION_TRUST_FAILED |
| `actor_type` | enum: END_USER / RP_API / ADMIN / SYSTEM |
| `actor_id` | text (tenant_user_id 또는 admin_id) |
| `subject_type` | text |
| `subject_id` | text |
| `payload` | jsonb |
| `prev_hash` | text — 이 tenant의 직전 row의 row_hash |
| `row_hash` | text — `SHA256(prev_hash \| tenantId \| eventType \| canonical(payload))` 의 base64url |
| `created_at` | composite PK 구성 컬럼 — 후속 Interval Partitioning 시 partition key로 사용 |

**hash chain은 per-tenant**. 글로벌 단일 chain은 다중 서버 환경에서 single-writer 병목.

#### `admin_user` (`admin.domain.AdminUser`) — RLS 비대상

어드민 콘솔 사용자. RLS 비적용 (로그인 시점엔 tenant 컨텍스트가 아직 없음).

| 컬럼 | 의미 |
|------|------|
| `tenant_id` | NULL = `PLATFORM_OPERATOR`, 값 있으면 `RP_ADMIN` |
| `email` | unique |
| `password_hash` | bcrypt |
| `role` | enum: `PLATFORM_OPERATOR` / `RP_ADMIN` |
| `status` | `ACTIVE` / `SUSPENDED` |
| `last_login_at` | |

DB CHECK 제약으로 `role`/`tenant_id` 정합성 강제:
```sql
CHECK ((role='PLATFORM_OPERATOR' AND tenant_id IS NULL)
    OR (role='RP_ADMIN'           AND tenant_id IS NOT NULL))
```

---

## 4. 마이그레이션 흐름 (Flyway)

v1.5 Oracle 이식 시 구 PostgreSQL의 다중 V 파일(V1~V18)을 **단일 baseline으로 통합**했다. 구 history는 `server/src/main/resources/db/archive_postgres/`에 보존.

```
V1__oracle_baseline           DB user 3-tier(APP_MIGRATOR/APP_RUNTIME/APP_ADMIN),
                              PASSKEY_CTX secure application context,
                              passkey_ctx_pkg(set_tenant/clear_tenant) 패키지,
                              passkey_tenant_predicate 정책 함수,
                              전체 테이블·인덱스 DDL (tenant, tenant_user,
                              tenant_webauthn_config, credential,
                              tenant_attestation_policy, api_key, audit_log,
                              admin_user, refresh_token, scheduler_lease 등),
                              DML grant, audit funnel 인덱스

R__vpd_policies               7개 tenant-scoped 테이블에 DBMS_RLS.ADD_POLICY 부착.
                              테이블 배열이 desired state — 파일 hash 변경 시 재적용.
```

새 tenant-scoped 테이블 추가 절차는 `server/docs/migrations.md` "VPD conventions" 참조. `audit_log`는 단일 테이블이며, EE 환경에서는 Interval Partitioning을 후속 마이그레이션으로 부착할 수 있다.

---

## 5. 요청 한 건의 흐름

### 5.1 모든 요청에 공통

```
HTTP request
  │
  ▼
TraceIdFilter (order = HIGHEST_PRECEDENCE)
    - X-Trace-Id 헤더 echo 또는 새 UUID16 발급
    - MDC traceId set, finally remove
  │
  ▼
TenantResolutionFilter (HIGHEST_PRECEDENCE + 10)
    - 등록된 TenantResolver들을 순회 (Order=0 ApiKeyTenantResolver → HeaderTenantResolver)
    - 첫 번째 match가 TenantContextHolder.set
    - finally remove (스레드풀 누수 방지)
  │
  ▼
RateLimitFilter (HIGHEST_PRECEDENCE + 20)
    - /api/* 만 적용. /actuator, /_diag 제외
    - PathClass enum (REGISTER / AUTHENTICATE / ADMIN_LOGIN / DEFAULT)으로 URI 1회 분류
    - Bucket key는 보통 tenantId 기반, /api/v1/admin/auth/login 만 source IP 기반 (5/min)
    - Redis Lua INCR+EXPIRE atomic 단일 round-trip (75초 TTL)
    - 초과 시 BusinessException(R001) → 429
    - 실제 client IP는 Tomcat RemoteIpValve가 X-Forwarded-For/X-Forwarded-Proto 기반으로 치환
      (server.forward-headers-strategy=framework, internal-proxies CIDR로 LB 신뢰)
  │
  ▼
Spring Security FilterChain (4 chains by URL, Order 1~4)
    - Order 1 — /api/v1/admin/**  → 세션 쿠키 (Spring Session Redis, Secure/HttpOnly/SameSite=Lax/
                                    Path=/api/v1/admin) + CSRF (cookie Secure/SameSite=Lax/
                                    HttpOnly=false for SPA) + form login
                                    + 헤더: HSTS, CSP(default-src 'none'+frame-ancestors 'none'+
                                    base-uri 'none'+form-action 'self'), X-Frame-Options=DENY,
                                    Referrer-Policy=strict-origin-when-cross-origin
    - Order 2 — /api/v1/rp/**     → ApiKeyAuthenticationFilter (X-API-Key + Argon2 verify)
                                    → 미인증/잘못된 키 → 401 A005
                                    + 헤더: HSTS, CSP(default-src 'none'+frame-ancestors 'none'),
                                    Referrer-Policy=no-referrer
    - Order 3 — /actuator/health, /info, /_diag, /v3/api-docs, /swagger-ui — permit all
                                    (prod에서는 springdoc.api-docs.enabled=false로 swagger 차단)
                                    + 헤더: HSTS + X-Frame-Options=DENY + Referrer-Policy=no-referrer
    - Order 4 — /actuator/**       → HTTP basic, hasRole(ACTUATOR), 헤더는 Order 2와 동일
  │
  ▼
Controller → Service (@Transactional)
  │
  ▼
JPA Repository
  │
  ▼
Hibernate MultiTenantConnectionProvider.getConnection(tenantId)
    - CALL passkey_ctx_pkg.set_tenant(?)  ← VPD secure context 설정. connection 반납 시 clear_tenant로 명시 해제
  │
  ▼
SQL 실행 — VPD predicate (tenant_id = HEXTORAW(SYS_CONTEXT('PASSKEY_CTX','TENANT_ID')))
```

### 5.2 RP 등록 ceremony (passkey 등록)

```
브라우저
  │  user clicks "Register passkey"
  │
  ▼  ① POST /api/v1/rp/passkeys/register/options
     X-API-Key: pk_<prefix>.<secret>
     { externalUserId, displayName }
  │
  ▼  ApiKeyAuthenticationFilter (rp Security chain Order 2, prod 한정 strict)
     │  - X-API-Key 누락/잘못 → 401 (A005)
     │  - ApiKeyService.verify (Caffeine cache → miss 시 Argon2)
     │  - 성공 시 SecurityContext에 ApiKeyAuthenticationToken + TenantContextHolder.set
     │
  ▼  RegistrationService.beginRegistration()
     │
     ├─ TenantWebauthnConfigService.requireCurrent()  → RP ID, origins, UV 정책
     ├─ TenantUser 없으면 생성
     ├─ 32바이트 random challenge 생성, ChallengeStore.save → Redis (TTL 5분)
     │       key = "passkey:challenge:<tenantId>:<ceremonyId>"
     └─ PublicKeyCredentialCreationOptions JSON 반환 (challenge base64url)
  │
  ▼  ② navigator.credentials.create({ publicKey: ... })
     - 사용자가 인증기 (Touch ID, 보안 키 등)로 새 키쌍 생성
     - clientDataJSON, attestationObject 반환
  │
  ▼  ③ POST /api/v1/rp/passkeys/register/verify
     { ceremonyId, credentialId, clientDataJsonB64u, attestationObjectB64u, transports, nickname }
  │
  ▼  RegistrationService.finishRegistration()
     │
     ├─ ChallengeStore.consume(ceremonyId)  → Redis에서 한 번만 꺼냄 (replay 방지)
     ├─ ChallengeRecord.ceremonyType == REGISTRATION 확인
     ├─ ServerProperty(origins, rpId, challenge) 구성
     ├─ WebAuthnManager.parse(RegistrationRequest)
     ├─ WebAuthnManager.verify(regData, params)
     │     ❌ DataConversionException → ATTESTATION_INVALID (P003)
     │     ❌ VerificationException   → ATTESTATION_INVALID (P003)
     ├─ AAGUID 추출 → TenantAttestationPolicy.accepts(aaguid)
     │     ❌ false → AAGUID_NOT_ALLOWED (P008)
     ├─ AttestedCredentialDataConverter.convert(acd) → bytes로 직렬화
     ├─ Credential.create(...) → DB insert (RLS 적용, @PrePersist가 tenant_id 자동 set)
     ├─ AuditService.appendAfterCommit(CREDENTIAL_REGISTERED)
     │     → ceremony txn commit 후 auditExecutor 풀에서 비동기 append
     │     → 실패 케이스(ATTESTATION_TRUST_FAILED 등)는 동기 append로 컴플라이언스 보존
     └─ CeremonyMetrics.registrationSuccess.increment()
  │
  ▼  201 { credentialDbId, credentialId, aaguid }
```

### 5.3 RP 인증 ceremony + JWT 발급

```
브라우저
  │  user clicks "Sign in with passkey"
  │
  ▼  ① POST /api/v1/rp/passkeys/authenticate/options
     X-API-Key: ...
     { externalUserId? }                            ← null이면 discoverable credential 흐름
  │
  ▼  AuthenticationService.beginAuthentication()
     ├─ challenge 생성, ChallengeStore.save → Redis
     ├─ externalUserId 있으면 해당 user의 ACTIVE credential들 allowCredentials로
     └─ AuthenticationOptions JSON 반환
  │
  ▼  ② navigator.credentials.get({ publicKey: ... })
     - 사용자가 등록된 키로 challenge 서명
     - authenticatorData, signature, userHandle 반환
  │
  ▼  ③ POST /api/v1/rp/passkeys/authenticate/verify
     { ceremonyId, credentialId, clientDataJsonB64u, authenticatorDataB64u, signatureB64u, userHandleB64u? }
  │
  ▼  AuthenticationService.finishAuthentication()
     ├─ ChallengeStore.consume  → CeremonyType == AUTHENTICATION 확인
     ├─ credentialRepo.findByCredentialId
     │     ❌ 없음 → CREDENTIAL_NOT_FOUND (P006)
     │     ❌ REVOKED → CREDENTIAL_REVOKED (P007)
     ├─ stored bytes → AttestedCredentialData 복원
     ├─ AuthenticatorImpl(acd, NoneAttestationStatement, storedCounter) 생성
     ├─ ServerProperty + AuthenticationParameters 구성
     ├─ WebAuthnManager.parse + verify
     │     ❌ → ASSERTION_INVALID (P004) + metrics.authenticationFailure
     ├─ Credential.updateSignatureCounter(newCounter)
     │     ❌ newCounter ≤ storedCounter (둘 다 0 제외)
     │       → SIGNATURE_COUNTER_REGRESSION (P005, 401)
     │       → AuditService.append(SIGNATURE_COUNTER_REGRESSION)
     │       → metrics.signatureCounterRegression.increment()
     ├─ TokenService.issue(tenantId, tenantUserId, externalUserId)
     │     → JWT access (15분) + refresh (30일). 서명 알고리즘은 passkey.jwt.algorithm
     │       (HS256 default / RS256). RS256 시 공개키는 /.well-known/jwks.json 노출
     ├─ AuditService.appendAfterCommit(CREDENTIAL_AUTHENTICATED)
     │     → afterCommit 비동기; counter regression 등 실패는 동기 append 유지
     └─ metrics.authenticationSuccess.increment()
  │
  ▼  200 { credentialDbId, tenantUserId, accessToken, refreshToken, accessExpiresIn, signatureCounter }
```

### 5.4 어드민 콘솔 로그인 → 작업

```
브라우저(콘솔)
  │
  ▼  ① POST /api/v1/admin/auth/login
     Content-Type: application/json
     { "email": "ops@crosscert.local", "password": "..." }
  │
  ▼  JsonLoginAuthenticationFilter
     - JSON body를 username/password 요청 파라미터로 wrap
  │
  ▼  Spring Security UsernamePasswordAuthenticationFilter
     - AdminUserDetailsService.loadUserByUsername(email)
     - BCryptPasswordEncoder.matches(rawPwd, passwordHash)
  │
  ▼  AdminAuthenticationSuccessHandler
     - AdminPrincipal(adminId, tenantId, role) 생성
     - SecurityContext에 enriched Authentication set
     - admin.recordLogin()
     - JSESSIONID 쿠키 발급
     - 200 { adminId, role }
  │
  ▼  ② GET /api/v1/admin/tenants  (PLATFORM_OPERATOR만)
     Cookie: JSESSIONID=...
  │
  ▼  Spring Security가 세션에서 AdminPrincipal 복원
     │
  ▼  AdminTenantController.list()
     ├─ AdminAuthz.requirePlatformOperator() — role 검증
     └─ AdminTenantService.listAll() → adminDataSource 사용 가능 (APP_ADMIN — EXEMPT ACCESS POLICY)
  │
  ▼  ③ POST /api/v1/admin/tenants/{tenantId}/api-keys
  │
  ▼  AdminApiKeyController.issue()
     ├─ AdminAuthz.requireTenantAccess(tenantId)
     │     - PLATFORM_OPERATOR: 무조건 통과
     │     - RP_ADMIN: principal.tenantId == pathTenantId 확인 → ADMIN_ROLE_FORBIDDEN (M002)
     │     - 통과 후 TenantContextHolder.set(pathTenantId) — 이후 SQL은 RLS 적용
     ├─ ApiKeyService.issue()
     │     - random prefix + secret 생성
     │     - Argon2id hash 저장
     │     - **plaintext는 응답 객체에만, DB에 안 저장**
     └─ AuditService.append(API_KEY_ISSUED)
  │
  ▼  201 { id, plaintext: "pk_aB3xY7Q9.<secret>", prefix, name }
     ⚠️ plaintext는 이 응답에서만 노출. 콘솔이 사용자에게 "지금만 복사하세요" 표시 필요.

  ④ GET /api/v1/admin/tenants/{tenantId}/audit-logs/verify?from=...&to=...
     ▼  AdminAuditController.verify()
        ├─ AdminAuthz.requireTenantAccess(tenantId)
        └─ AuditService.verifyIntegrity(tenantId, from, to)
              → AuditEntryRepository.streamForTenantByTime (fetchSize=1000 hint)
              → 각 row의 SHA-256 hash chain 재계산 후 stored row_hash / prev_hash 비교
              → ChainVerification { verifiedRows, tamperedEntryIds[] }
     ▼  200 { tenantId, from, to, verifiedRows, tamperedEntryIds }
     `AuditChainScheduler`가 매일 03:30 UTC에 동일 로직을 모든 tenant에 자동 실행 →
     tampered != [] 시 audit.chain.tampered Micrometer counter + ERROR 로그.
```

---

## 6. 핵심 invariants

코드가 진화해도 깨지면 안 되는 불변식 (다수가 ArchUnit/integration test로 자동 검증):

1. **모든 DB 접근은 `@Transactional` 안에서만**. 이유: Hibernate `getConnection(tenantId)`은 트랜잭션 진입 시점에 한 번 호출되어 `passkey_ctx_pkg.set_tenant`로 VPD 컨텍스트를 설정. 트랜잭션 밖이면 컨텍스트 미설정 → VPD fail-closed.
2. **모든 테넌트 스코프 테이블은 `DBMS_RLS.ADD_POLICY`로 VPD 정책 부착**. `R__vpd_policies.sql`의 테이블 배열이 desired-state.
3. **`APP_RUNTIME`은 `EXEMPT ACCESS POLICY` 미부여**. 운영 트래픽에 VPD 강제. `APP_ADMIN`만 부여(Platform Operator cross-tenant).
4. **tenant 컨텍스트 미설정 → SELECT 0 rows (fail-closed)**. 정책 함수 `passkey_tenant_predicate`가 컨텍스트 부재 시 `'1 = 0'` predicate 반환.
5. **RP API 인증의 정석은 `ApiKeyAuthenticationFilter` (Spring Security)**. `ApiKeyTenantResolver`는 local/test/dev에서만 보조. prod의 미인증 요청은 401(A005)로 항상 막힘.
6. **Hibernate `getConnection(tenantId)`에서 `set_tenant` 단일 지점**, connection 반납 시 `clear_tenant`. 다른 곳에서 VPD 컨텍스트를 직접 조작하지 말 것 — Oracle 컨텍스트는 per-session이라 누수 위험.
7. **`ApiResponse` envelope 모든 응답에 적용**. controller는 직접 `ResponseEntity` 반환 금지 (`/api/v1/admin/auth/login` 같은 Spring Security 자체 응답만 예외).
8. **VPD 정책은 `R__vpd_policies.sql`로 desired-state 관리**. 새 테이블 추가 시 같은 PR에서 R__ 배열 + `RlsPolicyCatalogTest.EXPECTED_TABLES` 갱신.
9. **URL prefix `/api/v1/rp/`, `/api/v1/admin/`, `/_diag/` 세 그룹만 허용** — ArchUnit 강제.
10. **`ErrorCode`는 단일 enum + 도메인 prefix(C/A/T/P/R/D/M) + 3자리 번호**. 추가 시 prefix 규약 유지.
11. **`Credential.updateSignatureCounter`만이 signature counter 변경 진입점**. 단조 증가 검사를 우회하지 말 것. 단위 테스트 `CredentialSignatureCounterTest`가 4개 시나리오로 강제.
12. **API key의 plaintext는 DB에 절대 저장 안 됨**. Argon2id hash만 보관. `ApiKeyService.verify`는 `DUMMY_HASH`로 항상 같은 시간 소비 (timing attack 방어). 캐시는 Caffeine `LoadingCache` single-flight — 동일 키 동시 요청에서도 Argon2 verify 1회만 실행.
13. **audit hash chain은 per-tenant + `DBMS_LOCK`(ALLOCATE_UNIQUE + REQUEST X_MODE, release_on_commit)으로 직렬화**. 같은 tenant의 concurrent ceremony가 chain fork를 일으키지 않음 (구 PG `pg_advisory_xact_lock`의 Oracle 등가물). 무결성 검증은 `AuditService.verifyIntegrity(tenantId, from, to)` + 일별 `AuditChainScheduler`(03:30 UTC)가 자동 실행 → 위변조 발견 시 `audit.chain.tampered{tenantId}` Micrometer counter + ERROR 로그.
14. **JWT 검증은 `verifyAccess` / `verifyRefresh` 둘 중 하나로 명시 호출**. `typ` claim이 안 맞으면 INVALID_TOKEN — refresh 토큰을 access처럼 쓰는 혼동 차단. JWT secret은 `JwtProperties`가 부팅 시 ≥32 bytes를 강제 (fail-fast).
15. **API key 캐시 evict는 `ApiKeyRevocationPublisher.publish`** 거쳐 Redis pub/sub로 모든 인스턴스 동기화.
16. **Ceremony 성공 audit는 `appendAfterCommit`(afterCommit + `@Async("auditExecutor")`), 실패/규제 audit는 동기 `append`**. 비동기 append 실패는 ERROR 로그로 남으며 일별 scheduler가 chain gap을 발견하면 reconcile 대상이 됨.
17. **클라이언트 IP는 Tomcat `RemoteIpValve`를 통해서만 신뢰**. `server.forward-headers-strategy=framework` + `server.tomcat.remoteip.internal-proxies` CIDR에 들어있는 hop이 set한 X-Forwarded-For만 client IP로 채택. CIDR 밖에서 들어온 헤더는 무시 → admin-login rate limit이 LB hop 1개로 좁아지지 않음.
18. **모든 응답에 보안 헤더**. HSTS (`max-age=31_536_000; includeSubDomains`), `X-Frame-Options=DENY`, CSP (`default-src 'none'`+`frame-ancestors 'none'`; admin chain은 `form-action 'self'` 추가), Referrer-Policy. Swagger는 prod에서 `springdoc.api-docs.enabled=false`로 차단되므로 CSP가 깨질 일 없음.

---

## 7. 의존성 맵

```
Spring Boot 3.5.0
  ├ Web (Tomcat)
  ├ Validation (Hibernate Validator)
  ├ Data JPA (Hibernate 6.6 with multi-tenancy=DATABASE)
  ├ Data Redis (Lettuce 클라이언트)
  ├ Security (form login + session + httpBasic for actuator)
  ├ Session Redis (spring-session-data-redis) — multi-instance admin sessions
  └ Actuator (health, prometheus)

webauthn4j 0.27.0.RELEASE                ceremony 검증 코어 (+ webauthn4j-metadata: MDS3)
JJWT 0.12.6                              JWT HS256 발급/검증 (legacy verify path)
nimbus-jose-jwt 9.40                     JWT RS256 서명 (kid 헤더) + JWKS
Argon2 (de.mkammerer:argon2-jvm 2.11)    API key 시크릿 해시 (ApiKeyProperties로 파라미터 외부화)
Caffeine                                 ApiKeyService LoadingCache (single-flight, 5분 TTL)
Flyway core + flyway-database-oracle     스키마 마이그레이션 (Oracle variant)
springdoc-openapi 2.8.9                  OpenAPI/Swagger UI 자동 생성 (prod disabled by default)
Lombok                                   @Getter, @RequiredArgsConstructor, @Slf4j

Oracle JDBC (ojdbc11 23.3)               runtime
Testcontainers 1.20.4                    통합 테스트 (현재 사용 안함, docker-compose로 대체)
ArchUnit 1.3.0                           패키지 경계 검증

빌드/품질 도구
  Spotless 6.25.0 + Google Java Format 1.22.0   포맷팅 강제 (./gradlew check 에 포함)
  ErrorProne 2.27.1 (net.ltgt.errorprone 3.1.0) 정적 분석 — 현재 warn-only
  JaCoCo 0.8.11                                  coverage 리포트 (gate는 미적용)
```

---

## 8. 운영 모드 차이

| 항목 | local | test | dev | prod |
|------|-------|------|-----|------|
| `HeaderTenantResolver` (X-Tenant-Id) | ✅ | ✅ | ✅ | ❌ |
| `ApiKeyTenantResolver` (보조, X-API-Key) | ✅ | ✅ | ✅ | ❌ |
| `ApiKeyAuthenticationFilter` (Spring Security, X-API-Key) | ✅ | ✅ | ✅ | ✅ |
| `RateLimitFilter` (Lua atomic INCR+EXPIRE) | ✅ default | ❌ disabled | ✅ | ✅ |
| `/api/v1/admin/auth/login` rate limit | 5/min IP | n/a | 5/min IP | 5/min IP |
| `/_diag/whoami` | ✅ | ❌ | ✅ | ❌ |
| `passkey.admin.enabled` (adminDataSource) | false (default) | false | env | env |
| Spring Session store | redis | none | redis | redis |
| Session/CSRF cookie `Secure` flag (`PASSKEY_COOKIE_SECURE`) | false | n/a | true | true |
| Tomcat RemoteIpValve / `forward-headers-strategy` | framework | framework | framework | framework |
| Actuator `/prometheus`, `/env`, etc. | basic auth | n/a | basic auth | basic auth (+ 네트워크 차단 권고) |
| JWT secret 검증 (`JwtProperties` ≥32B) | ✅ | ✅ | ✅ | ✅ fail-fast |
| Swagger UI (`springdoc.swagger-ui.enabled`) | ✅ | n/a | ✅ | ❌ (env로 강제 차단) |
| Security headers (HSTS/CSP/XFO/Referrer) | ✅ | ✅ | ✅ | ✅ |
| `AuditChainScheduler` 일별 자동 검증 | ✅ | n/a | ✅ | ✅ (03:30 UTC) |
| `auditExecutor` 비동기 풀 (성공 ceremony audit) | ✅ | ✅ | ✅ | ✅ |
| Hikari pool size (`PASSKEY_HIKARI_POOL_MAX`) | 10 | 5 | env (20) | env (20) |

### 8.1 로깅

**MDC 키 4종**:

| 키 | 주입 시점 | 설명 |
|----|----------|------|
| `traceId` | `TraceIdFilter` (HIGHEST) | X-Trace-Id echo 또는 UUID16 신규 발급. 모든 로그 라인에 포함 |
| `tenantId` | `TenantResolutionFilter`(dev) / `ApiKeyAuthenticationFilter`(prod) | RP 요청 식별 |
| `adminId` | `AdminAuthenticationSuccessHandler` (login) + `AdminMdcFilter` (요청 단위 재주입) | 어드민 활동 추적 |
| `apiKeyId` | `ApiKeyAuthenticationFilter` | RP API key 호출 추적 — revoke 시 grep 키 |

로그 패턴: `[%X{traceId:-},%X{tenantId:-},%X{adminId:-},%X{apiKeyId:-}]`

**로그 컨벤션** (dot-notation prefix, JSON에서도 grep 친화적):
- `http` (AccessLogFilter — per-request 한 줄: method, path, status, durationMs + MDC 컨텍스트)
- `register.begin`, `register.success`, `register.attestation.invalid`, `register.aaguid.rejected`, `register.syncable.rejected`, `register.challenge.wrong_type`
- `auth.begin`, `auth.success`, `auth.assertion.invalid`, `auth.signature_counter.regression` (reason=`DOWNGRADE_TO_ZERO|REPLAY|BACKWARDS`), `auth.backup_state.synced` (WARN), `auth.backup_state.unsynced` (INFO), `auth.challenge.wrong_type`, `auth.credential.ratelimit.exceeded`
- `apikey.auth.{accept,reject}` (reason=`missing_header|verify_failed|tenant_inactive`), `apikey.issued`, `apikey.revocation.{published,received,malformed}`
- `admin.login.{success,failure}`, `admin.unauthenticated`, `admin.access_denied`, `admin.tenant.created`, `admin.apikey.revoke`, `authz.denied`
- `rp.unauthorized`, `ratelimit.exceeded`
- `challenge.{save,consume.miss}`, `audit.append`, `audit.append.async.failed`
- `credential.{rename,revoke}` (admin path), `credential.rename.rp`, `credential.revoke.rp` (RP-facing, ownership 통과), `credential.ownership.mismatch` (WARN — IDOR 시도 시그널)
- `token.refresh.{unknown_jti,verify.unknown_jti,verify.revoked,verify.expired,reuse_detected,tid_mismatch}` (보안 이벤트), `jwt.verify.{failed,previous_secret_used,wrong_typ}`
- `audit.chain.verify.{start,done,error}`, `audit.chain.tampered` (ERROR — 위변조 의심)
- `vpd.context.{set,unset,clear.failed}` (DEBUG / TRACE) — Oracle VPD application context lifecycle
- `mds.{provider.constructed,refresh.success,scheduled.refresh.failed,warmup.failed}`, `register.{mds.strict.engaged,mds.unavailable,mds.trust_failed,authenticator.revoked}`
- `passkey.boot.{ready,cookie.note,mds.misconfig,ratelimit.disabled}` (BootSanityLogger — ApplicationReadyEvent 시 단일 환경 덤프)

**레벨 정책**:
- `ERROR` — 무결성 위협 의심 (`auth.signature_counter.regression` clone 가능성, `token.refresh.reuse_detected` token reuse)
- `WARN` — 보안 이벤트 (로그인 실패, authz denied, ratelimit 초과, attestation invalid, `apikey.auth.reject reason=verify_failed`, `credential.ownership.mismatch`, `auth.backup_state.synced` compliance 시그널, `token.refresh.tid_mismatch`)
- `INFO` — 정상 흐름 핵심 (register/auth begin & success, admin 작업, apikey 발급, `credential.revoke.rp`, `http` 2xx/3xx/4xx, `auth.backup_state.unsynced`)
- `DEBUG` — 진단 (challenge save, audit.append, `apikey.auth.reject reason=missing_header`, VPD context lifecycle)
- `TRACE` — VPD tenant set per-tx (대량, prod에서 항상 OFF)

**메트릭** (`/actuator/prometheus`):
- `passkey.registration{outcome}`, `passkey.authentication{outcome}` — ceremony 결과 counter
- `passkey.signature_counter_regression` — 자동 revoke 시그널 (reason별 분리는 로그/audit에서)
- `passkey.backup_state.flips{direction=synced}` — CTAP 2.1 BS false→true. compliance dashboard용. UNSYNCED는 카운팅 안 함
- `passkey.security.ownership_mismatch` — RP-facing IDOR 시도 (rename/revoke가 다른 사용자 키 대상)
- `passkey.security.refresh_tid_mismatch` — cross-tenant refresh 시도 (token exfil 또는 confused-deputy)
- `passkey.security.refresh_reuse_detected` — 이미 rotate된 refresh 재제출 → family burn
- `audit.chain.tampered` — hash chain 위변조 의심
- 권장 알람 (참고): tid_mismatch ≥1 즉시 page, ownership_mismatch 5분 10건↑ warn, refresh_reuse_detected 5분 3건↑ warn

**profile별 appender** (`logback-spring.xml`):
- `!prod` (local/test/dev): Console만, `com.crosscert.passkey` DEBUG
- `prod`: 3-track 분리
  - `CONSOLE_JSON_WARN_SYNC` — WARN+ 동기 stdout (queue overflow 시에도 보안 이벤트 무유실)
  - `ASYNC_CONSOLE_JSON` — INFO/DEBUG 비동기 stdout (WARN+ DENY 필터로 중복 제거)
  - `ASYNC_FILE` — RollingFile `logs/passkey-server.log` (100MB×14일, totalSizeCap 5GB, gzip) — forensic 백스톱
  - root INFO, Hibernate SQL WARN, dedicated logger `access` INFO

**PII 마스킹**: 모든 로그 안전 처리는 `common.log.LogSanitiser`로 일원화 — `forLog(s)`는 CR/LF 치환 + 1024자 truncate (log injection + 로그 폭주 방어), `maskEmail(s)`는 `a***@domain.com` 형태로 local-part 마스킹, `truncateUserAgent(s)`는 128자, `shortId(s)`는 last-8. 도메인 코드는 LogSanitiser를 static import로만 호출.

---

## 9. 추가 자료

- [통합 가이드 (RP 개발자용)](./integration-guide.md)
- [에러 코드 카탈로그](./error-codes.md)
- [배포 가이드](./deployment.md)
- [정적 분석 보고서 + 35개 이슈 처리 현황](./analysis-report.md)
- [DB 마이그레이션 컨벤션](../server/docs/migrations.md)
- [원본 PRD](../multi-tenant-passkey-server-prd.md)
- [원본 액션 플랜 (M1~M5 위크 단위)](../multi-tenant-passkey-server-action-plan.md)
- [API Response 표준 (M1에서 채택)](../spring-boot-api-response-template.md)

OpenAPI spec은 서버 부팅 후:
- `http://localhost:8080/v3/api-docs` (JSON)
- `http://localhost:8080/swagger-ui/index.html` (UI)

---

## 10. FIDO MDS3 통합

### 10.1 개요

기본 동작은 webauthn4j non-strict — attestation cert chain 검증 안 함, AAGUID allow/deny 정책만으로 약식 통제. 위조 하드웨어 키, compromised authenticator를 직접 차단하지는 못함.

**MDS3 통합 후** (`passkey.mds.enabled=true` + tenant `mdsStrict=true`):
- 등록 시 FIDO Alliance가 서명한 metadata BLOB의 trust anchor로 attestation cert chain 검증
- BLOB의 `StatusReport`가 `REVOKED`, `ATTESTATION_KEY_COMPROMISE`, `USER_VERIFICATION_BYPASS` 등 critical 상태인 authenticator는 자동 거절
- `NOT_FIDO_CERTIFIED`는 정책으로 toggle (`passkey.mds.allow-not-fido-certified`, 기본 true — 비인증 통과 + WARN 로그)

### 10.2 BLOB 라이프사이클

```
1. boot                        MdsBlobProvider.@PostConstruct warmUp()
                                 └→ FidoMDS3MetadataBLOBProvider.refresh()
                                      └→ HTTPS GET https://mds3.fidoalliance.org/
                                      └→ JWT signature verify (FIDO Global Root CA)
                                      └→ parse → MetadataBLOB.entries
2. every 04:00 (cron)          MdsRefreshScheduler.scheduledRefresh()
3. register flow (strict 시)   MetadataBLOBBasedTrustAnchorRepository.find(aaguid)
                                 └→ provider.provide() → current BLOB의 entry
                                 └→ entry.statusReports critical → BadStatusException → AUTHENTICATOR_REVOKED
                                 └→ entry 없음 → TrustAnchorNotFoundException → MDS_TRUST_FAILED
                                 └→ trust anchor 반환 → DefaultCertPathTrustworthinessVerifier가 cert chain 검증
```

**Fail mode**:
- BLOB 한 번도 fetch 못 함 + strict tenant: `MDS_UNAVAILABLE` (503)
- BLOB은 있지만 scheduled refresh 실패: stale BLOB 유지 (fail-open) — last-known-good으로 운영 지속
- Root CA PEM 부재: 부팅 시 `IllegalStateException` (fail-closed)

### 10.3 tenant strict 활성화

`tenant_attestation_policy.mds_strict` (V10, BOOLEAN DEFAULT FALSE) admin API:
```
PUT /api/v1/admin/tenants/{tenantId}/attestation-policy
{
  "mode": "ANY",
  "allowedAaguids": [],
  "deniedAaguids": [],
  "mdsStrict": true
}
```

strict on이지만 서버 `passkey.mds.enabled=false`면 해당 tenant의 register 요청은 `P011 MDS_UNAVAILABLE`로 즉시 실패. RP가 준비된 후 점진 전환 가능 (다른 tenant에 영향 없음).

### 10.4 운영 체크리스트

| 항목 | 확인 방법 |
|------|----------|
| Root CA PEM 배포 | `passkey.mds.root-certificate-path`가 가리키는 파일 존재 + `openssl x509 -text -noout`으로 subject 확인 |
| BLOB 첫 fetch | `GET /_diag/mds-status` → `status: READY` + `entryCount > 0` |
| 매일 refresh | `mds.refresh.success` 로그 1회/일 + `lastFetched` 24h 이내 |
| Refresh 실패 alert | `mds.scheduled.refresh.failed` ERROR 로그 → Prometheus alert rule |
| Strict tenant 거절 분포 | audit log `ATTESTATION_TRUST_FAILED` 집계 — 정상 사용자 거절 시 정책 재검토 |
| Audit chain 무결성 (별개 시스템이지만 운영자 동일) | `audit.chain.verify.done` 로그 매일 1회 + `audit.chain.tampered` counter = 0. 위반 시 즉시 alert + DBA 감사 |

### 10.5 운영 모드 차이 (§8 표 보완)

| 항목 | local | test | dev | prod |
|------|-------|------|-----|------|
| `passkey.mds.enabled` | false (env) | false | env | env (false 권장 초기, RP 준비 후 true) |
| `MdsBlobProvider` 빈 | 조건부 | 조건부 | 조건부 | 조건부 |
| `MdsRefreshScheduler` cron | 04:00 | n/a | 04:00 | 04:00 |
| `strictWebAuthnManager` 빈 | enabled true 시 | n/a | enabled true 시 | enabled true 시 |

---

## 11. 변경 이력

| 일자 | 마일스톤 / wave | 주요 변경 |
|------|----------------|----------|
| 2026-05-15 | M1~M5 초기 | 멀티테넌트 RLS, WebAuthn 코어, JWT, RP API key, audit log, admin REST API, JS SDK |
| 2026-05-15 | Hardening Waves 1~5 | audit chain advisory lock, ApiKeyAuthenticationFilter, JWT typ 검증, prefix collision retry + timing 평탄화, admin upsert 실제 반영, findAll → paged tenant-scoped, Spring Session Redis, actuator chain 분기, Caffeine 캐시 + Redis pub/sub, 도메인 invariant 단위 테스트, V9 funnel index, admin login dedicated rate-limit, log injection 방어 |
| 2026-05-15 | Observability | 보안/흐름/외부의존성 로그 보강 (`@Slf4j` 14개 확장), MDC 4종 (`traceId/tenantId/adminId/apiKeyId`) — `AdminMdcFilter` + `ApiKeyAuthenticationFilter` 주입, prod logback profile (Async + JSON + RollingFile), §8.1 로깅 컨벤션 문서화 |
| 2026-05-15 | FIDO MDS3 통합 | `credential.metadata` 패키지 신설 (`MdsBlobProvider` + `MdsRefreshScheduler` + `MdsTrustAnchorRepositoryConfig`), `webauthn4j-metadata:0.27` 의존성, V10 `tenant_attestation_policy.mds_strict` 컬럼, strict `WebAuthnManager` 빈 + `RegistrationService` 분기, ErrorCode 3종(P010 `MDS_TRUST_FAILED`, P011 `MDS_UNAVAILABLE`, P012 `AUTHENTICATOR_REVOKED`) + audit event `ATTESTATION_TRUST_FAILED`, `/_diag/mds-status` |
| 2026-05-16 | Quality/Performance/Security Hardening | **SEC-1**: `AuditService.verifyIntegrity(tenantId, from, to)` + `AuditEntryRepository.streamForTenantByTime` + `GET /api/v1/admin/tenants/{id}/audit-logs/verify` + 일별 `AuditChainScheduler` (03:30 UTC) + `audit.chain.tampered` Micrometer counter. **SEC-2**: Tomcat `RemoteIpValve` 활성화 (`server.forward-headers-strategy=framework` + `tomcat.remoteip.*`) → admin-login rate limit이 실제 client IP 기반. **SEC-3**: `application.yml`에서 JWT secret default 제거 (prod fail-fast). **SEC-4/5**: CSRF + Spring Session cookie `Secure`/`SameSite=Lax`/`Path=/api/v1/admin` 명시. **SEC-6**: `application-prod.yml`에서 springdoc/swagger-ui disabled. **SEC-7**: HSTS + CSP (`default-src 'none'`) + frame-ancestors + Referrer-Policy를 모든 chain에 적용. **PF-1**: `RateLimiter`를 Lua `INCR+EXPIRE` atomic 단일 round-trip으로 전환. **PF-2**: `AuditService.appendAfterCommit` + `@Async("auditExecutor")` + DLQ 로깅 — ceremony 성공 audit가 hot path에서 비동기. 실패 audit는 동기 유지(컴플라이언스). **PF-3**: `ApiKeyService.verifiedCache`를 `LoadingCache`로 전환 — single-flight로 cache stampede 방지. **PF-4**: Hikari pool size 환경변수화 (`PASSKEY_HIKARI_POOL_MAX`). **PF-5**: `RateLimitFilter.PathClass` enum으로 URI 1회 분류. **CQ-1**: `AdminSecurityConfig.writeError`를 ObjectMapper + `ApiResponse.error` 사용으로 전환. **CQ-3**: TS SDK `unwrap()`에 content-type/JSON 파싱 가드 + `transports.split` null/빈 처리. **CQ-4**: ErrorProne + JaCoCo plugin 도입 (warn-only). **CQ-5**: `ApiKeyProperties`, `WebauthnCeremonyProperties`, `RateLimitProperties.adminLoginPerMinute` 신설로 Argon2 파라미터/challenge length/admin-login limit 외부화. **CQ-6**: `common.log.LogSanitiser` 통합 (forLog + maskEmail). **CQ-7**: Service 핵심 public method Javadoc. unit test 4개 추가 (`AuditServiceVerifyIntegrityTest`, `RateLimiterTest`, `RateLimitFilterTest`, `ApiKeyServiceTest`, `LogSanitiserTest`). Spring Security 6 deprecation: `AntPathRequestMatcher` → `PathPatternRequestMatcher`. |
| 2026-05-16 | Admin Console v0.1 (`admin/` 신규) | Vite 5 + React 18 + TS + Tailwind + shadcn/ui + TanStack Query 5 + React Router 6 SPA. 별도 도메인 `admin.passkey.example.com` 전제. 기능: PLATFORM_OPERATOR / RP_ADMIN 2 role 자동 라우팅, Tenants list+create, WebAuthn config / AAGUID 정책 (chip 입력 + mdsStrict 토글), API Keys (발급 → plaintext **1회만** 노출 모달 + 체크박스 강제), Credentials (페이지된 목록 + 클라이언트 검색 + revoke), Audit Log (eventType 필터 + payload modal) + **Hash chain Verify 패널** (날짜 범위 → intact 배지 + tampered row highlight), Funnel (windowDays 카드). 서버 호환 변경: `AdminSecurityConfig.cors(...)` + `CorsConfigurationSource` bean (`passkey.admin.console-origin` allowlist), `CookieCsrfTokenRepository` SameSite property화 (`passkey.cookie.same-site`), `server.servlet.session.cookie.same-site` prod=`none`/local=`lax`. `unit/admin/AdminCorsConfigTest` 추가. SPA 빌드 산출물 gzipped ≈185 KB (lazy chunk 9종), nginx 정적 호스팅 (`Dockerfile` multi-stage + `nginx.conf` 보안 헤더). 단위 테스트 8건 (api unwrap + format util), e2e Playwright spec 5종 (M5에서 docker-compose backend wire-up 후 활성화 예정). 설계 문서: `admin-console-docs/admin-console-prd.md` + `admin-console-docs/admin-console-action-plan.md`. 운영 의존: `PASSKEY_ADMIN_CONSOLE_ORIGIN`, `PASSKEY_COOKIE_SAME_SITE`, `PASSKEY_SESSION_SAME_SITE` env 설정 + 운영팀 도메인 정책 (별도 호스트 vs 같은 etld+1) 합의 필요. |
| 2026-05-18 | Oracle 이식 (v1.5) | PG RLS → Oracle 19c VPD 전면 이식. `V1__oracle_baseline.sql` + `R__vpd_policies.sql` 단일 baseline, PG migration history는 `db/archive_postgres/` 보존. `passkey_ctx_pkg` secure application context + `MultiTenantConnectionProvider`가 `set_tenant`/`clear_tenant` 호출 (HikariCP 반납 시 누수 방지). DB user 3-tier — `APP_MIGRATOR`(Flyway)/`APP_RUNTIME`(VPD 적용)/`APP_ADMIN`(`EXEMPT ACCESS POLICY`). Audit chain advisory lock은 `DBMS_LOCK.ALLOCATE_UNIQUE + DBMS_LOCK.REQUEST(X_MODE, release_on_commit=TRUE)` 로 PG `pg_advisory_xact_lock` 대체. Audit 테이블은 EE에서 Interval Partitioning 후속 적용 가능. `RlsPolicyCatalogTest`가 VPD 정책 catalog 검증. |
| 2026-05-18 | Spec / Security P0~P1 (RP IDOR + CTAP 2.1) | **PR1**: `RegistrationOptionsResponse.excludeCredentials` (NON_EMPTY 직렬화 — 신규 user 영향 0). **PR2**: CTAP 2.1 BS flag 추적 — `Credential.updateBackupState`, `AuditEventType.CREDENTIAL_BACKUP_STATE_CHANGED`, direction 분리 (`auth.backup_state.synced` WARN / `.unsynced` INFO). **PR3 (BREAKING)**: RP-facing `/api/v1/rp/passkeys/{id}` rename(body `externalUserId`) / revoke(query `externalUserId`)에 ownership 검증 — `CredentialLifecycleService.renameForUser/revokeForUser`, `RpCredentialRenameRequest` 신설, admin path는 기존 `rename(UUID, String)` / `revoke(UUID, reason)` 보존. mismatch는 enumeration 방어를 위해 `P006`로 응답. **PR4**: signature counter regression 세분화 (`Credential.RegressionReason.DOWNGRADE_TO_ZERO/REPLAY/BACKWARDS`) — `auth.signature_counter.regression` 로그/audit payload에 `reason` 필드. **PR5**: `UserVerificationPolicy.isStrictRequired()` 신설 — REQUIRED만 strict, PREFERRED/DISCOURAGED는 best-effort 의도 명시. **PR6**: `TokenService.rotate`에 ambient TenantContext vs JWT `tid` claim 일치 검증, 위반 시 `token.refresh.tid_mismatch` WARN + clientIp/userAgent + `INVALID_TOKEN`. ArchUnit Rule 2 allow-list에 `..auth.jwt..` 추가. **PR7**: `user.id` (WebAuthn) 인코딩을 UUID 텍스트(36 byte) → raw 16 byte로 전환 — 신규 등록만 적용, 기존 row 동거. **PR8**: SDK `@crosscert/passkey-sdk` v0.2.0 — `excludeCredentials` 전달, `renameCredential(id, externalUserId, nickname)` / `revokeCredential(id, externalUserId)` 신설. 부수: 이전 세션의 `BootSanityLogger`가 `common.log`에서 5개 도메인 import해 ArchUnit Rule 1 위반 → `infrastructure.bootlog`로 이동. 단위 테스트 신설/확장: `CredentialBackupStateTest`(3), `CredentialLifecycleServiceOwnershipTest`(5), `TokenServiceRotateTenantMismatchTest`(2), `UserVerificationPolicyTest`(3), `regression_detail_carries_*`(3), `RegistrationServiceTest.userHandle/excludeCredentials`(3). |
| 2026-05-18 | Observability Wave 2 | 신규 메트릭: `passkey.backup_state.flips{direction=synced}` (compliance dashboard), `passkey.security.ownership_mismatch` (IDOR 알람), `passkey.security.refresh_tid_mismatch` (cross-tenant exfil), `passkey.security.refresh_reuse_detected` (token reuse). 신규 운영 이벤트: `auth.backup_state.synced` (WARN) / `.unsynced` (INFO), `credential.ownership.mismatch` (WARN), `credential.revoke.rp` (INFO — admin path와 구분), `token.refresh.tid_mismatch` (WARN, clientIp/UA 포함), `token.refresh.reuse_detected` (ERROR, clientIp/UA 포함). 신규 인프라: `AccessLogFilter` (per-request INFO/WARN/ERROR — method, path, status, durationMs, MDC 컨텍스트), `BootSanityLogger` (`ApplicationReadyEvent` 시 profile/MDS/Argon2/rate-limit/cookie/JWT 단일 INFO 라인 + 위험 조합 WARN), `ApiKeyAuthenticationFilter` 인증 실패 경로별 WARN(`apikey.auth.reject reason=verify_failed|tenant_inactive`)으로 분리, `TokenService.parseSigned` 실패/타입혼동 WARN, `ChallengeStore.consume.miss` DEBUG→INFO 승격, register/auth `challenge.wrong_type` WARN. `logback-spring.xml` prod profile — WARN+ sync `CONSOLE_JSON_WARN_SYNC`로 분리해 async queue overflow 시에도 보안 이벤트 무유실. |
| 2026-05-21 | Audit self-invocation 수정 + Cross-tenant 통계 | **Audit 버그**: `AuditService.appendAfterCommit`이 `afterCommit` 콜백에서 `appendAsync`를 self-invocation으로 호출 → Spring AOP 프록시 우회로 `@Async`·`@Transactional(REQUIRES_NEW)` 무력화 → ceremony 완료 audit(`CREDENTIAL_REGISTERED`/`CREDENTIAL_AUTHENTICATED`)가 트랜잭션 없이 실행되어 VPD fail-closed로 유실, admin 대시보드 ceremony 성공률 0% 표시. 수정: `appendAsync`를 별도 빈 `AsyncAuditWriter`로 분리 (프록시 경계 통과 → `@Async` 정상 작동, 위임된 `auditService.append()`도 cross-bean이라 `REQUIRES_NEW` 복원), `AuditService ↔ AsyncAuditWriter` 생성자 순환은 `@Lazy`로 차단. 회귀 테스트 `AsyncAuditWriterSliceTest`(audit-* executor 스레드 검증). **Cross-tenant 통계**: `/tenants` 페이지 MetricCard 3종(등록 Credential / 유효 API Key / 24h ceremony)을 전체 테넌트 합산 실데이터로 연동. `GET /api/v1/admin/platform/stats` 신규 — `AdminPlatformStatsController` + `AdminPlatformStatsService` (둘 다 `@ConditionalOnProperty(passkey.admin.enabled=true)`), `APP_ADMIN` 데이터소스 + native COUNT 3건으로 VPD 우회 cross-tenant 집계 (`ApiKeyAdminWriter` 패턴 재사용, `@Transactional("adminTransactionManager")`). PLATFORM_OPERATOR 전용 (`requirePlatformOperator()`). 프론트: `TenantsListPage` `useQuery`(staleTime 60s), `lib/format`에 `formatCount`/`formatMaybeCount` 공통 추출. 테스트: `AdminPlatformStatsControllerSliceTest`(권한·응답 계약), `AdminPlatformStatsIntegrationTest`(2 테넌트 합산·ACTIVE 필터·24h 윈도우 — `AdminEnabledIntegrationTestBase`가 `@DynamicPropertySource`로 `passkey.admin.enabled=true` + `APP_ADMIN` 데이터소스 등록, 공유 `test` 프로파일 미오염), `AdminDataSourceConditionTest`에 빈 부재 가드 추가. |
| 2026-05-22 | Admin End-user 조회 | Admin 콘솔 tenant 상세에 "Users" 탭 추가 — end-user(`tenant_user`) 목록·검색·상세를 조회 전용으로 제공. 신규 `AdminEndUserController` (`GET /api/v1/admin/tenants/{tenantId}/users` 목록, `.../users/{tenantUserId}` 상세) — `AdminUserSessionController`의 logout-all과 같은 base path를 HTTP 메서드 차이로 공존. `TenantUserRepository.findByTenantIdWithSearch` — `EndUserRow` projection + `Credential` LEFT JOIN 집계로 활성 passkey 개수를 N+1 없이 계산(GROUP BY라 `countQuery` 명시), externalId·displayName case-insensitive 검색. `AuditAggregationService.lastEventForSubject`로 상세의 최근 활동 시각. 프론트: `UsersTab`(검색·페이징 목록), `UserDetailPage`(별도 라우트 `users/:tenantUserId` 상세 — 메타 카드 + passkey 테이블). 권한 `requireTenantAccess` — PLATFORM_OPERATOR + 자기 tenant RP_ADMIN. 테스트: `AdminEndUserControllerSliceTest`(6 케이스 — 목록·검색 전달·상세·cross-tenant 거부·404·RP_ADMIN 거부), `AdminEndUserIntegrationTest`(2 테넌트 시딩 — 활성 passkey 집계·검색·격리·countQuery 정합성). |
| 2026-05-20 | RP Java SDK (`sdk-java/` 신규) | RP **백엔드**용 Java SDK 신설 — `passkey-rp-sdk-core`(transport·DTO·`NimbusJwtVerifier`), `passkey-rp-spring-boot-starter`(ceremony 프록시 컨트롤러 + `PasskeyJwtAuthenticationFilter` + auto-config), `passkey-rp-sdk-bom`. RP는 starter 의존성만 추가하면 `/passkey/{register,authenticate}/{begin,finish}` ceremony 엔드포인트와 JWT 인증 필터를 거의 무코드로 확보. `examples/passkey-rp-demo`는 in-memory user store 기반 참조 RP 서버. **JWT 검증은 RS256 + JWKS 전용** — `NimbusJwtVerifier`가 `<base-url>/.well-known/jwks.json`에서 공개키를 가져와 로컬 검증(secret 공유 불필요). 문서: `docs/rp-java-sdk.md`. |
| 2026-05-22 | RS256 JWT 운영 모드 | `passkey.jwt.algorithm`을 `RS256`으로 전환 가능 — RP Java SDK(`NimbusJwtVerifier`)가 RS256/JWKS 전용이므로 RP SDK 통합이 있으면 서버는 RS256 운영 필수. `TokenService`는 cutover 호환을 위해 HS256·RS256 양쪽 검증을 모두 수용, `JwksController`가 `/.well-known/jwks.json`으로 RS256 공개키 노출. local 프로파일(`application-local.yml`)을 RS256 + 데모 RSA 키페어로 기동하도록 변경. 운영 환경변수 `PASSKEY_JWT_ALGORITHM` / `PASSKEY_JWT_RSA_{PRIVATE,PUBLIC}_PEM` / `PASSKEY_JWT_KID`(+ `_PREVIOUS` 회전용) — `docs/deployment.md` "JWT 서명 알고리즘" 참조. |
