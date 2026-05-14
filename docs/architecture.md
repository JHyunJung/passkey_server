# Architecture & Entity Reference

Crosscert Passkey Server의 내부 구조 문서. **누가** 어떤 데이터를 들고 있고, **요청 하나가** 어떤 경로로 흐르는지를 한 문서에서 빠르게 파악할 수 있도록 정리했습니다.

대상 독자: 새로 합류한 백엔드 개발자, 보안 리뷰어, 인프라 담당자.

---

## 1. 시스템 개요

```
                           ┌──────────────────────────┐
   브라우저(RP 프론트)  ──→ │ RP 백엔드 (API key 보유)  │ ──→  Passkey Server
                           └──────────────────────────┘            │
                                                                    ▼
   카드사 IAM 담당      ──→  Passkey Admin Console SPA  ──→  Passkey Server
   (RP_ADMIN)                  (v1.1, REST는 완비)              │
                                                                ▼
   Crosscert 운영자     ──→  동일 콘솔, 권한만 다름      ──→  PostgreSQL + Redis
   (PLATFORM_OPERATOR)
```

- **단일 Spring Boot 인스턴스**(stateless, 수평 확장 가능)
- **PostgreSQL** — 모든 영속 데이터. Row-Level Security로 테넌트 격리.
- **Redis** — WebAuthn challenge 임시 저장(TTL 5분), rate-limit 카운터.
- **외부 통신** — 없음. MDS BLOB 통합은 v1.1로 deferral.

---

## 2. 패키지 구조

```
com.crosscert.passkey
├── PasskeyApplication                main()
├── common
│   ├── response                     ApiResponse, ErrorDetail, FieldError, PageResponse
│   ├── exception                    ErrorCode (단일 enum), BusinessException, GlobalExceptionHandler
│   └── filter                       TraceIdFilter
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
│   ├── challenge                    ChallengeStore (Redis), ChallengeRecord, CeremonyType
│   ├── webauthn                     WebAuthnConfig (bean), Base64UrlCodec
│   ├── service                      RegistrationService, AuthenticationService,
│   │                                CredentialLifecycleService, TenantWebauthnConfigService
│   ├── controller                   RegistrationController, AuthenticationController,
│   │                                CredentialController
│   ├── repository                   *Repository
│   └── metrics                      CeremonyMetrics (Micrometer counters)
├── auth                             — M3 Auth
│   ├── jwt                          JwtProperties, JwtConfig, TokenService, TokenPair
│   └── apikey
│       ├── domain                   ApiKey, ApiKeyStatus
│       ├── repository               ApiKeyRepository
│       ├── service                  ApiKeyService (issue/verify, Argon2id)
│       └── resolver                 ApiKeyTenantResolver (X-API-Key 헤더)
├── ratelimit                        RateLimitProperties, RateLimiter (Redis fixed-window), RateLimitFilter
├── audit                            — M3 audit log
│   ├── domain                       AuditEntry (composite PK, partitioned), AuditEventType, ActorType
│   ├── repository                   AuditEntryRepository
│   └── service                      AuditService (per-tenant SHA-256 hash chain)
├── admin                            — M4 Admin Console backend
│   ├── domain                       AdminUser, AdminRole, AdminStatus
│   ├── repository                   AdminUserRepository
│   ├── security                     AdminPrincipal, AdminUserDetailsService,
│   │                                AdminAuthenticationSuccessHandler, JsonLoginAuthenticationFilter,
│   │                                AdminSecurityConfig, AdminAuthz
│   ├── service                      AdminTenantService
│   └── controller                   AdminMe/Tenant/ApiKey/WebauthnConfig/AttestationPolicy/
│                                    Credential/Audit/Funnel Controllers
└── infrastructure
    ├── jpa
    │   ├── BaseEntity                id + createdAt + updatedAt
    │   ├── TenantScopedEntity        BaseEntity + tenant_id (@PrePersist 자동 주입)
    │   ├── JpaConfig                 placeholder
    │   └── multitenancy
    │       ├── TenantConnectionProvider          매 트랜잭션에 SET LOCAL app.current_tenant
    │       ├── CurrentTenantIdentifierResolverImpl  ThreadLocal → tenantId 문자열
    │       └── HibernateMultiTenancyConfig       Hibernate property 주입
    ├── datasource
    │   └── DataSourceConfig          runtimeDataSource (@Primary), adminDataSource (@Conditional)
    └── web
        └── WebFilterConfig           TraceIdFilter → TenantResolutionFilter → RateLimitFilter 순서 pin
```

### 패키지 경계 — ArchUnit 강제

`server/src/test/java/.../architecture/PackageArchitectureTest.java`가 PR마다 검증:

1. `common.*`은 도메인 패키지(`tenant`, `auth`, `credential`, `audit`, `admin`) import 금지 — 역방향 의존 차단.
2. `TenantContextHolder` 접근은 명시된 패키지에서만 (resolver, context, JPA infra, service, admin.security, ratelimit, audit.service, challenge).
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
       ├──→ N  audit_log              ── partitioned by month, hash chain per tenant
       │      (event_type, payload jsonb, prev_hash → row_hash)
       │
       └──→ 0..N  admin_user          ── RLS 비대상 (로그인은 컨텍스트 set 전)
              (tenant_id NULL = PLATFORM_OPERATOR)
```

### 3.2 RLS 정책 요약

| 테이블 | RLS | 정책 식 | 비고 |
|--------|-----|---------|------|
| `tenant` | ❌ | — | resolver/admin이 lookup 시작점 |
| `tenant_user` | ✅ ENABLE+FORCE | `tenant_id = passkey.current_tenant_id()` | |
| `tenant_webauthn_config` | ✅ | 동일 | |
| `tenant_attestation_policy` | ✅ | 동일 | |
| `credential` | ✅ | 동일 | |
| `audit_log` | ✅ (parent + 모든 partition) | 동일 | partition 추가 시 자동 상속 |
| `api_key` | ❌ | — | prefix lookup이 컨텍스트 set 전. Argon2 hash가 실제 게이트. |
| `admin_user` | ❌ | — | 로그인 lookup이 컨텍스트 set 전. application authz가 게이트. |

`passkey.current_tenant_id()`는 `current_setting('app.current_tenant')`를 읽어 `NULLIF`로 빈 문자열을 NULL로 변환 → **컨텍스트 미설정 시 모든 SELECT가 0 rows (fail-closed)**.

DB 역할 3-tier:
- `app_migrator` — Flyway 전용 owner
- `app_runtime` — `NOBYPASSRLS NOSUPERUSER`. RP API + RP Admin 트래픽.
- `app_admin` — `BYPASSRLS NOSUPERUSER`. Platform Operator의 cross-tenant 조회 (M4부터 활성).

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

#### `audit_log` (`audit.domain.AuditEntry`) — partitioned + hash chain

month-partitioned. composite PK `(id, created_at)` — Postgres partitioning 요구사항.

| 컬럼 | 의미 |
|------|------|
| `id` | uuid |
| `tenant_id` | RLS key |
| `event_type` | enum: TENANT_CREATED, API_KEY_ISSUED/REVOKED, CREDENTIAL_REGISTERED/AUTHENTICATED/REVOKED/RENAMED, SIGNATURE_COUNTER_REGRESSION |
| `actor_type` | enum: END_USER / RP_API / ADMIN / SYSTEM |
| `actor_id` | text (tenant_user_id 또는 admin_id) |
| `subject_type` | text |
| `subject_id` | text |
| `payload` | jsonb |
| `prev_hash` | text — 이 tenant의 직전 row의 row_hash |
| `row_hash` | text — `SHA256(prev_hash \| tenantId \| eventType \| canonical(payload))` 의 base64url |
| `created_at` | partition key |

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

```
V1__baseline                  역할 3-tier, schema, pgcrypto extension,
                              passkey.current_tenant_id() 헬퍼 함수
V2__create_tenant             tenant, tenant_user (RLS enable+force)
V3__create_webauthn_config    RP ID/origin 설정
V4__create_credential         자격증명 본체
V5__create_attestation_policy AAGUID allowlist
V6__create_api_key            RP API key (RLS 비대상)
V7__create_audit_log          parent + 2026-05/06 초기 파티션
V8__create_admin_user         admin 사용자

R__rls_policies               모든 정책의 desired state (re-applied on file hash change)
```

운영 주의: `audit_log`의 미래 월 파티션은 운영 cron이 미리 생성해야 함. V7 헤더 코멘트 참조.

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
    - Redis 카운터 INCR, 60초 TTL
    - 초과 시 BusinessException(R001) → 429
  │
  ▼
Spring Security FilterChain (3 chains by URL)
    - /api/v1/admin/**  → 세션 쿠키 + CSRF + form login
    - /api/v1/rp/**     → stateless, permit all (인증은 TenantResolver가 끝낸 상태)
    - 기타              → permit all (actuator/swagger/diag)
  │
  ▼
Controller → Service (@Transactional)
  │
  ▼
JPA Repository
  │
  ▼
Hibernate MultiTenantConnectionProvider.getConnection(tenantId)
    - SELECT set_config('app.current_tenant', ?, true)  ← SET LOCAL은 COMMIT/ROLLBACK 시 자동 소멸
  │
  ▼
SQL 실행 — RLS USING (tenant_id = passkey.current_tenant_id())
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
  ▼  RegistrationService.beginRegistration()
     │
     ├─ ApiKeyTenantResolver: prefix lookup → Argon2 verify → tenantId 확정
     ├─ TenantContextHolder.set(tenantId)  ← TenantResolutionFilter 안에서 발생
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
     ├─ AuditService.append(CREDENTIAL_REGISTERED) → audit_log
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
     │     → JWT access (15분) + refresh (30일), HS256
     ├─ AuditService.append(CREDENTIAL_AUTHENTICATED)
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
     └─ AdminTenantService.listAll() → adminDataSource 사용 가능 (BYPASSRLS)
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
```

---

## 6. 핵심 invariants

코드가 진화해도 깨지면 안 되는 불변식 (다수가 ArchUnit/integration test로 자동 검증):

1. **모든 DB 접근은 `@Transactional` 안에서만**. 이유: Hibernate `getConnection(tenantId)`은 트랜잭션 진입 시점에 한 번 호출되어 `SET LOCAL`을 발급. 트랜잭션 밖이면 RLS 미적용.
2. **모든 테넌트 스코프 테이블은 `ENABLE + FORCE ROW LEVEL SECURITY`**. `FORCE`가 빠지면 owner 권한일 때 정책이 무시됨.
3. **`app_runtime` 역할은 `NOBYPASSRLS NOSUPERUSER`**. 운영에서 RLS 강제.
4. **tenant 컨텍스트 미설정 → SELECT 0 rows (fail-closed)**. `passkey.current_tenant_id()`가 `NULLIF`로 빈 문자열을 NULL로 변환.
5. **`TenantResolver`는 인터페이스**. 현재 두 구현(API key + 로컬 헤더), M5 어드민 콘솔용 admin-session resolver를 더 추가 가능.
6. **Hibernate `getConnection(tenantId)`에서 `SET LOCAL` 단일 지점**. 다른 곳에서 `SET LOCAL`을 발급하지 말 것.
7. **`ApiResponse` envelope 모든 응답에 적용**. controller는 직접 `ResponseEntity` 반환 금지 (`/api/v1/admin/auth/login` 같은 Spring Security 자체 응답만 예외).
8. **RLS 정책은 `R__rls_policies.sql`로 desired-state 관리**. 새 테이블 추가 시 같은 PR에서 R__ 갱신.
9. **URL prefix `/api/v1/rp/`, `/api/v1/admin/`, `/_diag/` 세 그룹만 허용** — ArchUnit 강제.
10. **`ErrorCode`는 단일 enum + 도메인 prefix(C/A/T/P/R/D/M) + 3자리 번호**. 추가 시 prefix 규약 유지.
11. **`Credential.updateSignatureCounter`만이 signature counter 변경 진입점**. 단조 증가 검사를 우회하지 말 것.
12. **API key의 plaintext는 DB에 절대 저장 안 됨**. Argon2id hash만 보관.
13. **audit hash chain은 per-tenant**. 글로벌 단일 chain은 다중 서버 환경에서 single-writer 병목.

---

## 7. 의존성 맵

```
Spring Boot 3.5.0
  ├ Web (Tomcat)
  ├ Validation (Hibernate Validator)
  ├ Data JPA (Hibernate 6.6 with multi-tenancy=DATABASE)
  ├ Data Redis (Lettuce 클라이언트)
  ├ Security (form login + session)
  └ Actuator (health, prometheus)

webauthn4j 0.27.0.RELEASE                ceremony 검증 코어
JJWT 0.12.6                              JWT 발급/검증
Argon2 (de.mkammerer:argon2-jvm 2.11)    API key 시크릿 해시
Flyway 11.x (postgresql variant)         스키마 마이그레이션
springdoc-openapi 2.8.9                  OpenAPI/Swagger UI 자동 생성
Lombok                                   @Getter, @RequiredArgsConstructor, @Slf4j

PostgreSQL JDBC                          runtime
Testcontainers 1.20.4                    통합 테스트 (현재 사용 안함, docker-compose로 대체)
ArchUnit 1.3.0                           패키지 경계 검증
```

---

## 8. 운영 모드 차이

| 항목 | local | test | dev | prod |
|------|-------|------|-----|------|
| `HeaderTenantResolver` (X-Tenant-Id) | ✅ | ✅ | ✅ | ❌ |
| `ApiKeyTenantResolver` (X-API-Key) | ✅ | ✅ | ✅ | ✅ |
| `RateLimitFilter` | ✅ default | ❌ disabled | ✅ | ✅ |
| `/_diag/whoami` | ✅ | ❌ | ✅ | ❌ |
| `passkey.admin.enabled` (adminDataSource) | false (default) | false | env | env |
| JWT secret 검증 | ✅ (모든 profile) | ✅ | ✅ | ✅ fail-fast |
| Swagger UI | ✅ | n/a | ✅ | ❌ 권고 (LB에서 차단) |

---

## 9. 추가 자료

- [통합 가이드 (RP 개발자용)](./integration-guide.md)
- [에러 코드 카탈로그](./error-codes.md)
- [배포 가이드](./deployment.md)
- [DB 마이그레이션 컨벤션](../server/docs/migrations.md)
- [원본 PRD](../multi-tenant-passkey-server-prd.md)
- [원본 액션 플랜 (M1~M5 위크 단위)](../multi-tenant-passkey-server-action-plan.md)
- [API Response 표준 (M1에서 채택)](../spring-boot-api-response-template.md)

OpenAPI spec은 서버 부팅 후:
- `http://localhost:8080/v3/api-docs` (JSON)
- `http://localhost:8080/swagger-ui/index.html` (UI)
