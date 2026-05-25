# Admin / Passkey 앱 분리 + MDS 스케줄링 Admin 단독 소유 설계

작성일: 2026-05-25
작성자: brainstorming session
상태: 검토 중

## 0. 한 줄 요약

현재 단일 `server/` Spring Boot 앱과 별도 `admin/` React SPA로 구성된 운영체를 — Gradle multi-project로 분할하여 (`:common`, `:admin-app`, `:passkey-app`) Admin SPA를 `:admin-app`이 직접 서빙하고, 사용자 등록·인증 ceremony는 `:passkey-app`이 전담하며, MDS BLOB 갱신은 Admin이 단독 소유하여 Oracle 공유 저장소 + Redis pub/sub로 모든 Passkey 인스턴스를 다중화 환경에서도 일관되게 동기화한다.

## 1. 동기와 목표

### 1.1 현재 상태의 문제

1. **운영자 권한 코드와 ceremony 코드가 같은 JVM 안에 공존** — Spring Security misconfiguration 1줄로 두 영역 모두 노출 가능. 책임 경계가 코드 패키지 수준에만 존재.
2. **MDS refresh 스케줄러가 Passkey 인스턴스에 부착되어 다중화 부적합** — `@Scheduled` 기반 cron이 모든 Passkey 인스턴스에서 동시 fire되거나, leader election 없이 한 인스턴스만 fire되어도 그 인스턴스만 캐시가 새로워짐. N대 운영 시 strict tenant attestation 결과가 인스턴스마다 달라질 수 있음.
3. **설치형 납품 가능성**에 대한 사전 준비 부재 — 고객사마다 배포 토폴로지·버전·보안 요건이 다를 수 있는데, 현재 한 덩어리 코드베이스는 그것을 표현하지 못함. 컴파일 타임 경계 강제가 없어 산출물에 "관리자 권한 코드가 묻어 들어가는" 사고가 가능.

### 1.2 목표

1. **Admin 백엔드(`:admin-app`)와 Passkey 본체(`:passkey-app`)를 별도 Spring Boot 앱으로 분리** — 각자 자기 인증 모델만 보유, cross-contamination 0.
2. **MDS 스케줄러를 Admin이 단독 소유** — Admin이 검증·게시, Passkey N대가 구독. 다중화 환경에서 모든 인스턴스가 동일 BLOB 버전 보장.
3. **Admin SPA를 `:admin-app`이 직접 서빙** — nginx 별도 컨테이너 제거, 납품 단위 단순화.
4. **고객사가 부르는 외부 API 100% 호환** — `/api/v1/rp/**` URL·요청·응답·SDK 모두 변경 없음.
5. **점진적 마이그레이션** — 빅뱅 PR 금지, 메인 브랜치 항상 빌드·배포 가능.

### 1.3 의도적으로 안 하는 것 (Scope Out)

- DB 분리 (Oracle 인스턴스는 그대로 한 개, VPD로 격리 유지)
- S2S 자격증명 (Admin↔Passkey 직접 HTTP 호출 경로 자체를 만들지 않음)
- Service mesh / API gateway 도입
- Blue-green / canary 배포 전략
- 새 인증 모델 (운영자 세션쿠키 + X-API-Key 그대로)
- 새 FIDO2 코어 기능
- 라이선스 시스템 (별도 spec에서 다룸)

## 2. 핵심 결정

| # | 결정 | 근거 |
|---|------|------|
| D1 | 2-앱 납품 구조: `:admin-app` + `:passkey-app` | RP는 고객사 영역, 우리는 SDK만 제공. Admin과 Passkey만 우리가 운영·납품. |
| D2 | Gradle multi-project (`:common`, `:admin-app`, `:passkey-app`) | 설치형 납품 가능성. 컴파일 타임 경계 강제, 앱별 독립 버저닝·이미지 빌드. |
| D3 | Admin SPA를 `:admin-app`이 직접 서빙 | 납품 단위 ↓ (nginx 컨테이너 제거). Spring Boot가 정적 자산 + API 한 origin. |
| D4 | MDS 옵션 B: Admin이 검증·게시, Oracle 공유 저장소, 검증 끝난 JSON 저장 | Passkey 다중화 환경 일관성 보장이 최우선. Admin이 단일 검증 게이트키퍼. |
| D5 | 변경 감지: Redis pub/sub + 부팅 시 초기 read | Passkey 부하 최소(평시 DB 쿼리 0회), 기존 `ApiKeyRevocationPublisher` 패턴과 일치, 변경 전파 초 단위. |
| D6 | Admin↔Passkey S2S 자격증명 미구현 | 두 앱이 직접 HTTP로 만나는 경로가 0 (통신은 DB + pub/sub만). DB 권한(`APP_RUNTIME`/`APP_ADMIN`)이 경계 강제. YAGNI. |
| D7 | sample-rp는 `examples/sample-rp/` (빌드 그래프 밖) | SDK dogfood 용도 명확화. 납품 산출물 아님이 디렉터리 위치로 표명. |
| D8 | 점진적 6-Phase 마이그레이션 | 각 phase에서 메인 항상 빌드 가능, rollback 가능. 빅뱅 금지. |

## 3. 전체 아키텍처

### 3.1 시스템 구성도

```
┌────────────────── 우리(Crosscert)가 납품하는 것 ──────────────────┐
│                                                                  │
│   ┌──────────────────────┐         ┌─────────────────────────┐  │
│   │   :admin-app         │         │      :passkey-app       │  │
│   │   Spring Boot 3.5    │         │      Spring Boot 3.5    │  │
│   │                      │         │                          │  │
│   │  • /api/v1/admin/**  │         │  • /api/v1/rp/**        │  │
│   │  • Admin SPA 서빙     │         │    (고객사 RP 표면)        │  │
│   │  • 운영자 세션쿠키      │         │  • /.well-known/jwks   │  │
│   │  • MDS @Scheduled    │         │  • fido2 ceremony 코어   │  │
│   │  • Audit chain verify│         │  • MDS 구독              │  │
│   │  • RefreshToken청소   │         │    (Redis pub/sub)      │  │
│   └──────────┬───────────┘         └─────────┬───────────────┘  │
│              │                               │                   │
└──────────────┼───────────────────────────────┼───────────────────┘
               │  INSERT mds_blob_cache        │  SELECT mds_blob_cache
               │  audit_log INSERT             │  credential I/O
               │                               │  audit_log INSERT
               │                               │
               │           ┌──────────────────▼──────────────┐
               │           │       Oracle 19c (VPD)          │
               │           │                                  │
               │           │  • mds_blob_cache (NEW, platform│
               │           │    -scoped, APP_ADMIN write,    │
               │           │    APP_RUNTIME read)            │
               │           │  • tenant, credential, audit_   │
               │           │    log, api_key, admin_user,    │
               │           │    refresh_token, ... (VPD)     │
               │           │  • scheduler_lease              │
               │           └─────────────────────────────────┘
               │
               │  PUBLISH 'mds.blob.refreshed' {version}
               │           ┌─────────────────────────────────┐
               └──────────▶│  Redis 7                        │
                           │                                  │
                           │  • Spring Session (admin only)  │
                           │  • api-key cache eviction       │
                           │  • mds.blob.refreshed (NEW)     │
                           │  • rate limit (passkey only)    │
                           └─────────────────────────────────┘

┌──────────── 고객사 영역 (우리가 만들지 않음) ────────────┐
│                                                          │
│   [고객사 RP 백엔드]  ─ X-API-Key ──►  :passkey-app      │
│         │                                                │
│         └─ 우리가 제공한 sdk/ + sdk-java/ 사용             │
└──────────────────────────────────────────────────────────┘

[examples/sample-rp/] — 우리 레포의 SDK dogfood (빌드 그래프 밖)
```

### 3.2 책임 분담

| 앱 | 역할 | 외부 노출 | 인증 |
|---|---|---|---|
| `:admin-app` | 백오피스 운영 + MDS 게시 + audit chain verify + refresh token 청소 | `/api/v1/admin/**` + SPA 정적 자산 + `/actuator/health,info` | 운영자 세션쿠키 (Spring Session Redis) + CSRF |
| `:passkey-app` | FIDO2 ceremony 실행 + MDS 구독 + JWT 발급 | `/api/v1/rp/**`, `/.well-known/jwks.json`, `/actuator/health,info` | X-API-Key (고객사 RP 인증) |

### 3.3 두 앱 사이의 통신 채널

| 채널 | 방향 | 용도 |
|---|---|---|
| Oracle `mds_blob_cache` | Admin write → Passkey read | MDS BLOB 영속 전파 (source of truth) |
| Redis pub/sub `mds.blob.refreshed` | Admin publish → Passkey subscribe | 새 BLOB version 즉시 통지 (수 초 내 fan-out) |
| Oracle `audit_log` | 양쪽 write | 감사 기록 (per-tenant hash chain 공유) |
| Oracle `api_key` | Admin write → Passkey read | API key 발급/회수 |
| Redis pub/sub `apikey.revoked` | Admin publish → Passkey subscribe | API key Caffeine cache eviction (기존) |

**의도적으로 없는 채널**: Admin → Passkey HTTP 직접 호출. 모든 통신은 위 5개 채널 중 하나로만.

### 3.4 변경되지 않는 것

- Oracle VPD 멀티테넌트 격리 (7개 tenant-scoped 테이블, `passkey_ctx_pkg`)
- DB 사용자 3-tier (`APP_MIGRATOR`, `APP_RUNTIME`, `APP_ADMIN`)
- Audit hash chain (단일 테이블, per-tenant SHA-256, `DBMS_LOCK`)
- FIDO2 코어 로직 (`fido2.mds` 파서, ceremony 검증 — 패키지 위치만 이동)
- 고객사 외부 API 스펙 (`/api/v1/rp/**` URL·요청·응답 envelope 모두 호환)

## 4. Gradle Multi-Project 구조

### 4.1 디렉터리 레이아웃

```
Passkey/                                  ← 레포 루트
├── settings.gradle.kts                   ← include(":common", ":admin-app", ":passkey-app")
├── build.gradle.kts                      ← allprojects/subprojects 공통 설정
├── gradle.properties
├── docker-compose.yml
│
├── common/                               ← 라이브러리 (java-library)
│   ├── build.gradle.kts
│   └── src/main/java/com/crosscert/passkey/common/...
│
├── admin-app/                            ← Spring Boot #1 (납품)
│   ├── build.gradle.kts                  (spring-boot + node-gradle plugin)
│   ├── Dockerfile
│   └── src/main/java/com/crosscert/passkey/admin/
│       └── AdminApplication.java
│
├── passkey-app/                          ← Spring Boot #2 (납품)
│   ├── build.gradle.kts                  (spring-boot)
│   ├── Dockerfile
│   └── src/main/java/com/crosscert/passkey/passkey/
│       └── PasskeyApplication.java
│
├── admin-ui/                             ← Admin SPA (현재 admin/ rename)
│   ├── package.json
│   ├── vite.config.ts
│   └── src/                              ← React 코드 그대로
│
├── sdk/                                  ← npm @crosscert/passkey-sdk (그대로)
├── sdk-java/                             ← Maven 산출물 (그대로)
│
├── examples/
│   └── sample-rp/                        ← SDK dogfood (settings에 미포함)
│       ├── build.gradle.kts
│       └── src/
│
├── docs/
└── scripts/
```

### 4.2 settings.gradle.kts

```kotlin
rootProject.name = "passkey-platform"
include(":common", ":admin-app", ":passkey-app")
// examples/sample-rp는 별도 빌드, settings에 미포함
```

### 4.3 `:common` build.gradle.kts (핵심)

```kotlin
plugins {
    `java-library`
    id("io.spring.dependency-management")
}

dependencies {
    api("org.springframework.boot:spring-boot-starter-data-jpa")
    api("org.springframework.boot:spring-boot-starter-validation")
    api("com.oracle.database.jdbc:ojdbc11")
    api("org.flywaydb:flyway-core")
    api("io.micrometer:micrometer-registry-prometheus")
}
```

**`:common`은 `org.springframework.boot` plugin을 적용하지 않음** → fat JAR 안 만듦, `@SpringBootApplication` 없음.

### 4.4 코드 이동 매핑 (현재 → 새 위치)

| 현재 패키지 | 새 위치 | 비고 |
|---|---|---|
| `common/**` | `:common` | ApiResponse, ErrorCode, TraceIdFilter |
| `tenant/**` | `:common` | VPD context, MultiTenantConnectionProvider |
| `audit/domain/**`, `audit/repository/**` | `:common` | 엔티티 + read interface |
| `audit/service/AuditService` (write) | `:common` | 양쪽 다 INSERT |
| `audit/service/AuditChainScheduler` | `:admin-app` | 스케줄러는 Admin이 단독 소유 |
| `audit/controller/**` | `:admin-app` | 운영자 시야 |
| `auth/jwt/JwtConfig`, `TokenService`, `JwksController`, `TokenPair` | `:passkey-app` | 인증 ceremony에서 발급 |
| `auth/jwt/RefreshTokenCleanupScheduler` | `:admin-app` | 스케줄러는 Admin |
| `auth/jwt/repository/RefreshTokenRepository` (read) | `:common` | 양쪽 read |
| `auth/jwt/repository/RefreshTokenAdminWriter` | `:admin-app` | 운영자 강제 revoke |
| `auth/jwt/domain/**` | `:common` | 엔티티 |
| `auth/apikey/**` | `:passkey-app` | X-API-Key 인증 표면 |
| `ratelimit/**` | `:passkey-app` | 외부 표면 보호 |
| `credential/controller/**` (RP API) | `:passkey-app` | `/api/v1/rp/passkeys/**`, `/auth/**` |
| `credential/service/**` (ceremony) | `:passkey-app` | ceremony 로직 |
| `credential/domain/**` | `:common` | Admin도 조회 |
| `credential/repository/CredentialRepository` (ceremony) | `:passkey-app` | ceremony 시점 read/write |
| `credential/repository/CredentialAdminWriter` (bulk) | `:admin-app` | 관리자 강제 작업 |
| `credential/metadata/MdsProperties` | `:common` | yml binding, 양쪽 사용 |
| `credential/metadata/MdsBlobRefreshedEvent` | `:common` | Spring 이벤트 타입 |
| `credential/metadata/MdsBlobProvider` (구) | **분할** — 4.5 참조 |
| `credential/metadata/MdsRefreshScheduler` | `:admin-app` | 스케줄러 |
| `credential/metadata/MdsRevocationScanService` | `:admin-app` | DB write |
| `credential/metadata/MdsRevocationScanListener` | `:admin-app` | refresh 이벤트 listener |
| `credential/metadata/MdsDiagController` | `:admin-app` | `/_diag/mds-status` |
| `fido2/mds/**` (파서) | `:common` | `MetadataBlob.parse` 등 양쪽 사용 |
| `fido2/runtime/**` (ceremony 엔진) | `:passkey-app` | ceremony 검증 |
| `admin/**` (18 controller + 6 service) | `:admin-app` | 그대로 |
| `infrastructure/**` | `:common` | Hibernate config, DataSource |

### 4.5 `MdsBlobProvider` 분할

현재 한 클래스가 fetch + 검증 + 캐시를 다 수행. 세 컴포넌트로 분할:

| 새 클래스 | 위치 | 책임 |
|---|---|---|
| `MdsBlobPublisher` | `:admin-app` | FIDO MDS3 HTTP fetch + X.509 검증 + Oracle insert + Redis publish |
| `MdsBlobSubscriber` | `:passkey-app` | `ApplicationReadyEvent` 초기 read + Redis listener + 메모리 캐시 교체 |
| `MdsBlobStore` | `:common` | Oracle 테이블 read/write JPA + `MetadataBlob` 직렬화 |

### 4.6 ArchUnit 규칙 추가

기존 `PackageArchitectureTest`에 다음을 추가:

- `:admin-app`의 admin 패키지는 `fido2.runtime` import 금지 (ceremony 엔진 침범 방지)
- `:passkey-app`의 passkey 패키지는 admin 패키지 import 금지 (빌드 그래프가 이미 막지만 명시)
- `:common` 패키지는 admin/passkey 도메인 import 금지 (기존 규칙 유지)
- `@Scheduled` 어노테이션은 `:admin-app`에만 존재 (스케줄링 단일 소유 강제)
- `RestController` + `@RequestMapping("/api/v1/admin/**")` 는 `:admin-app`에만
- `RestController` + `@RequestMapping("/api/v1/rp/**")` 는 `:passkey-app`에만

### 4.7 빌드·기동 명령

```bash
# 인프라
docker compose up -d                            # Oracle + Redis

# 개발 기동 (다른 터미널)
./gradlew :admin-app:bootRun \
    --args='--spring.profiles.active=local'     # 8081 (SPA 정적 서빙 포함)
./gradlew :passkey-app:bootRun \
    --args='--spring.profiles.active=local'     # 8080

# SPA만 HMR 개발
cd admin-ui && npm run dev                      # 5173 → admin-app:8081로 proxy

# 빌드 산출물
./gradlew :admin-app:bootJar                    # admin-app-0.3.0.jar (SPA 포함)
./gradlew :passkey-app:bootJar                  # passkey-app-0.3.0.jar
./gradlew bootJar                               # 둘 다

# Docker 이미지
docker build -f admin-app/Dockerfile -t passkey-admin:0.3.0 .
docker build -f passkey-app/Dockerfile -t passkey-core:0.3.0 .

# 전체 검증
./gradlew check                                 # ArchUnit + slice + integration + spotless
```

## 5. MDS 데이터 플로우

### 5.1 평시 흐름 (자동)

```
[T+0]                  [T+~10s]               [T+~10.1s]            [T+~10.5s]
:admin-app             :admin-app             Oracle DB             :passkey-app × N
@Scheduled cron        FIDO MDS3 JWS    ───▶  INSERT into            (각 인스턴스)
04:00 UTC      ─────▶  fetch + X.509          mds_blob_cache         Redis SUBSCRIBE 수신
                       chain 검증              (new version)          → DB SELECT
                       + MetadataBlob.parse   COMMIT                 → JSON deserialize
                                              │                      → 캐시 atomic swap
                                              │ Redis PUBLISH
                                              ▼ 'mds.blob.refreshed'
                                              {version: N}
```

### 5.2 부팅 시 흐름

```
:passkey-app 부팅
    │
    ▼
ApplicationReadyEvent
    │
    ├─ Redis 채널 SUBSCRIBE 시작 (이제부터 publish 수신 가능) ← 먼저
    │
    └─ mds_blob_cache ORDER BY version DESC LIMIT 1 SELECT  ← 나중
        │
        ├─ 결과 있음 → 캐시 채움. 정상 가동.
        └─ 결과 없음 → 캐시 비어있는 상태. strict tenant fail-closed.
                     Admin 첫 publish로 자동 회복.
```

**Race condition 처리**: SUBSCRIBE 먼저, SELECT 나중. 이 순서면 어떤 타이밍이든 최신 version 놓치지 않음 (동일 version 중복 처리는 idempotent하므로 안전).

### 5.3 운영자 수동 트리거

```
Admin SPA  ──POST /api/v1/admin/mds/refresh (세션쿠키 + CSRF)──▶  :admin-app
                                                                │
                                                                ▼
                                                       MdsBlobPublisher.refreshNow()
                                                       (스케줄러가 호출하는 것과 동일)
                                                                │
                                                                ▼
                                                       audit_log INSERT
                                                       actor=admin-user:<id>
                                                       event=MDS_MANUAL_REFRESH
```

### 5.4 새 DB 스키마: `mds_blob_cache`

Flyway: `V<n>__mds_blob_cache.sql` (n은 Phase 5 시점 다음 번호)

```sql
-- Platform-scoped (tenant_id 없음, VPD 미적용)
CREATE TABLE mds_blob_cache (
  version          NUMBER(19)        NOT NULL,
  fetched_at       TIMESTAMP(6) WITH TIME ZONE NOT NULL,
  blob_no          NUMBER(10),
  next_update      DATE,
  entry_count      NUMBER(10)        NOT NULL,
  payload_json     CLOB              NOT NULL,
  created_by       VARCHAR2(120)     NOT NULL,
  created_at       TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
  CONSTRAINT pk_mds_blob_cache PRIMARY KEY (version)
);

CREATE INDEX idx_mds_blob_cache_version_desc
    ON mds_blob_cache (version DESC);

CREATE SEQUENCE mds_blob_cache_seq
    START WITH 1 INCREMENT BY 1 NOCACHE NOORDER;

-- 권한 모델 — DB 레이어가 경계 강제
GRANT SELECT          ON mds_blob_cache     TO APP_RUNTIME;  -- Passkey: read-only
GRANT SELECT, INSERT  ON mds_blob_cache     TO APP_ADMIN;    -- Admin: write 가능
GRANT SELECT          ON mds_blob_cache_seq TO APP_ADMIN;
```

**의미**:
- Passkey가 BLOB 변조 시도해도 DB 레이어에서 거부 (`APP_RUNTIME`은 INSERT 권한 없음)
- Admin이 단일 게이트키퍼임이 DB 권한으로도 강제됨
- S2S 자격증명 미구현에 대한 보안적 보상

**VPD 정책 미적용** — MDS BLOB은 모든 tenant 공유 플랫폼 자산. `R__vpd_policies.sql` 테이블 배열에 추가하지 않음. `RlsPolicyCatalogTest.EXPECTED_TABLES`에도 추가하지 않음. 이는 기존 `scheduler_lease` 테이블과 동일한 패턴.

### 5.5 payload_json 스키마

`MetadataBlob.entries()`를 Jackson `ObjectMapper`로 직렬화:

```json
{
  "no": 51,
  "nextUpdate": "2026-06-15",
  "entries": [
    {
      "aaguid": "08987058-cadc-4b81-b6e1-30de50dcbe96",
      "metadataStatement": { ... FIDO 표준 필드 ... },
      "statusReports": [
        {
          "status": "FIDO_CERTIFIED_L1",
          "effectiveDate": "2024-01-15",
          "certificateNumber": "...",
          "certificationDescriptor": "...",
          "url": "..."
        }
      ],
      "timeOfLastStatusChange": "2024-01-15"
    }
  ]
}
```

`:common`의 `MdsBlobSerde` 클래스가 양방향 직렬화 담당.

### 5.6 Redis pub/sub 메시지

**채널**: `mds.blob.refreshed` (기존 `apikey.revoked` 네이밍 컨벤션 일치)

**메시지**:
```json
{"version": 17, "fetchedAt": "2026-05-25T04:00:12Z"}
```

**핵심**: payload는 싣지 않음. version만. Redis pub/sub은 at-most-once 전달이므로 메시지 자체에 payload가 있으면 손실 시 BLOB도 손실. DB가 source of truth, Subscriber는 통지를 받으면 DB에서 직접 read.

### 5.7 컴포넌트 인터페이스

**`:common`**
```java
package com.crosscert.passkey.common.mds;

interface MdsBlobStore {
    Optional<MdsBlobRecord> findLatest();
    MdsBlobRecord findByVersion(long version);
    long insertNewVersion(MdsBlobRecord rec);  // APP_ADMIN만 호출 성공
}

record MdsBlobRecord(long version, OffsetDateTime fetchedAt,
                     Integer blobNo, LocalDate nextUpdate,
                     int entryCount, String payloadJson, String createdBy) {}

class MdsBlobSerde {
    String serialize(MetadataBlob blob);
    MetadataBlob deserialize(String json);
}

class MdsBlobRefreshedEvent { long version; }  // Spring application event
```

**`:admin-app`**
```java
@Component
@ConditionalOnProperty(name = "passkey.mds.enabled", havingValue = "true")
class MdsBlobPublisher {
    @Transactional
    PublishResult refreshNow(String actor);
}

@Component
@ConditionalOnBean(MdsBlobPublisher.class)
class MdsRefreshScheduler {
    @Scheduled(cron = "${passkey.mds.refresh-cron:0 0 4 * * *}")
    void scheduled();
}

@RestController
@RequestMapping("/api/v1/admin/mds")
class AdminMdsController {
    @PostMapping("/refresh")
    @PreAuthorize("hasRole('PLATFORM_OPERATOR')")
    ApiResponse<PublishResult> manualRefresh(@AuthenticationPrincipal AdminUser user);

    @GetMapping("/status")
    ApiResponse<MdsStatus> status();
}
```

**`:passkey-app`**
```java
@Component
@ConditionalOnProperty(name = "passkey.mds.enabled", havingValue = "true")
class MdsBlobSubscriber {
    @EventListener(ApplicationReadyEvent.class)
    void initialLoad();

    void onMessage(Message message);  // Redis listener

    MdsTrustAnchorSource trustAnchorSource();  // fido2 ceremony에 제공
}
```

### 5.8 메트릭

| 메트릭 | 위치 | 의미 |
|---|---|---|
| `mds.blob.publish.success` (counter) | admin-app | 성공한 게시 횟수 |
| `mds.blob.publish.failure` (counter, tagged `reason`) | admin-app | fetch/검증/DB 실패 |
| `mds.blob.publish.duration` (timer) | admin-app | 전체 게시 소요 |
| `mds.blob.cache.version` (gauge) | passkey-app | 현재 캐시 버전 (인스턴스별) |
| `mds.blob.cache.entry_count` (gauge) | passkey-app | 캐시된 엔트리 수 |
| `mds.blob.subscribe.events_received` (counter) | passkey-app | Redis 이벤트 수신 |
| `mds.blob.subscribe.db_loads` (counter) | passkey-app | DB read = 캐시 교체 횟수 |

**SLO**: 모든 Passkey 인스턴스의 `mds.blob.cache.version`이 동일. 한 인스턴스만 뒤처지면 alerting.

### 5.9 실패 시나리오

| 시나리오 | 결과 |
|---|---|
| Admin이 FIDO MDS3 fetch 실패 | `publish.failure` 증가, BLOB 그대로(stale 유지), 다음 cron 또는 운영자 재시도. Passkey 영향 0. |
| Admin이 검증 실패 (chain invalid) | DB insert 안 함. publish 안 함. Passkey는 직전 BLOB 유지. |
| Admin DB insert 후 Redis publish 실패 | DB는 최신, 이벤트 유실. Passkey 인스턴스는 다음 publish/재시작까지 stale. 메트릭 차이로 운영자 감지, 수동 재발행으로 회복. |
| Passkey 부팅 시 DB read 실패 | 캐시 비어있는 상태. strict tenant fail-closed. DB 복구 + 수동 publish로 회복. |
| Passkey가 Redis 이벤트 못 받음 (네트워크 글리치) | 다음 publish/재시작까지 stale. 메트릭으로 감지. |
| Admin DB insert 후 commit 전 다운 | 트랜잭션 롤백, 새 version 없음, publish 안 함. 정상. |

**모든 시나리오에서 worst case = "Passkey가 stale BLOB로 동작"** — 현재 코드의 stale 허용 정책과 일관. `MdsRefreshScheduler`의 주석 "Stale BLOB is intentionally kept"가 이미 명시.

### 5.10 보존·청소

`mds_blob_cache`는 단조 증가 누적. 평소 365건/년 — 부담 없음. 별도 청소 스케줄러는 본 spec 범위 밖 (YAGNI). 필요 시 추후 추가:

```sql
DELETE FROM mds_blob_cache WHERE version < (SELECT MAX(version) - 30 FROM mds_blob_cache);
```

## 6. 보안·인증 경계

### 6.1 두 앱 각자 자기 인증 모델만

**`:admin-app` SecurityConfig (3-chain)**
```
Order 1  /api/v1/admin/**            → 세션쿠키 + CSRF (Spring Session Redis)
Order 2  /actuator/health,info,
         /_diag/**, /swagger-ui/**,
         /static SPA assets          → permitAll
Order 3  /actuator/**                → HTTP Basic + hasRole(ACTUATOR)
Order 4  /**                         → SPA fallback (forward index.html)
```

**`:passkey-app` SecurityConfig (3-chain)**
```
Order 1  /api/v1/rp/**               → X-API-Key (Argon2id + Caffeine + Redis evict)
Order 2  /.well-known/jwks.json,
         /actuator/health,info,
         /_diag/**, /swagger-ui/**   → permitAll
Order 3  /actuator/**                → HTTP Basic + hasRole(ACTUATOR)
```

Cross-contamination 가능성 0. 한 앱이 자기가 모르는 인증 토큰을 받아도 거부.

### 6.2 SPA fallback 처리

`SpaForwardController`가 `/api/`로 시작하지 않는 점 없는 경로를 `index.html`로 forward:

```java
@Controller
class SpaForwardController {
    @GetMapping({"/", "/{path:[^.]*}", "/{path:[^.]*}/**"})
    public String forward(HttpServletRequest req) {
        if (req.getRequestURI().startsWith("/api/")) {
            throw new NoResourceFoundException(HttpMethod.GET, req.getRequestURI());
        }
        return "forward:/index.html";
    }
}
```

### 6.3 운영자 권한이 Passkey 표면에 도달하지 않음

- 운영자 세션쿠키 `PASSKEY_SESSION`은 `:admin-app`의 Spring Session Redis namespace에만 존재
- `:passkey-app`은 Spring Session 자체 미사용 (STATELESS) — 운영자 세션쿠키를 들고 와도 인식 불가
- 운영자 권한 우회 시도가 Passkey 표면에 도달할 채널이 없음

### 6.4 비밀(Secret) 격리

| 비밀 | admin-app | passkey-app |
|---|---|---|
| DB 비밀번호 (`APP_RUNTIME`) | ✗ | ✓ |
| DB 비밀번호 (`APP_ADMIN`) | ✓ | ✗ |
| Redis 비밀번호 | ✓ | ✓ |
| ACTUATOR HTTP Basic | ✓ | ✓ |
| JWT 서명 키 | ✗ | ✓ |
| FIDO MDS3 rootCa cert | ✓ | ✗ |
| ApiKey Argon2 pepper | ✗ | ✓ |

**Admin이 `APP_RUNTIME` 비밀번호 모름** = Passkey read-only 권한 우회 불가. **Passkey가 `APP_ADMIN` 비밀번호 모름** = MDS·credential bulk write 불가. DB 권한 + 비밀 격리가 이중 안전망.

### 6.5 CSRF

- `:admin-app` `/api/v1/admin/**` → CSRF 활성 (`CookieCsrfTokenRepository.withHttpOnlyFalse()`). SPA axios interceptor가 `XSRF-TOKEN` 쿠키 → `X-XSRF-TOKEN` 헤더 자동 복사.
- `:passkey-app` 전체 → CSRF 비활성 (모든 표면 stateless).

### 6.6 CORS

- `:admin-app`: 운영 same-origin → 비활성. local profile만 `http://localhost:5173` 허용 (Vite dev).
- `:passkey-app`: 본 모델은 고객사 RP **백엔드**가 부르는 것이라 원칙적으로 CORS 불필요. tenant별 origin 화이트리스트는 본 spec 범위 밖.

### 6.7 Audit logging — 분리 후 책임

| 이벤트 | 기록 위치 | actor |
|---|---|---|
| 운영자 로그인/로그아웃 | admin-app | `admin-user:<id>` |
| Tenant 생성/수정/삭제 | admin-app | `admin-user:<id>` |
| API key 발급/회수 | admin-app | `admin-user:<id>` |
| Credential 강제 SUSPEND | admin-app | `admin-user:<id>` or `scheduler:mds-revocation` |
| MDS publish (자동) | admin-app | `scheduler:mds-refresh` |
| MDS publish (수동) | admin-app | `admin-user:<id>` |
| Registration ceremony 성공/실패 | passkey-app | `end-user:<userHandle>` |
| Authentication ceremony 성공/실패 | passkey-app | `end-user:<userHandle>` |
| Refresh token 발급/revoke (자동) | passkey-app | `end-user:<userHandle>` |
| Refresh token 강제 revoke (운영자) | admin-app | `admin-user:<id>` |
| Audit chain verify (cron) | admin-app | `scheduler:audit-verify` |

`audit_log` 테이블은 공유 (VPD tenant-scoped). 두 앱이 같은 테이블에 INSERT. Hash chain은 per-tenant이므로 두 앱 동시 INSERT 안전 (기존 `DBMS_LOCK` 메커니즘 그대로).

### 6.8 OpenAPI 분리

- `:admin-app` `/v3/api-docs` → 운영자 endpoint만 노출
- `:passkey-app` `/v3/api-docs` → RP endpoint만 노출
- 고객사 RP 통합자가 운영자 endpoint 스펙을 볼 수 없음 (납품 시 정보 노출 감소)

## 7. 점진적 마이그레이션 Phasing

### 7.1 원칙

1. 메인 브랜치는 항상 빌드되고 배포 가능
2. 각 phase 끝에서 기존 기능 동작 (회귀 테스트 통과)
3. 고객사 SDK 호환성 100% 유지 (`/api/v1/rp/**` URL·요청·응답 envelope 불변)
4. Rollback 가능 (git revert로 복원)
5. DB 마이그레이션은 forward-only (Flyway)

### 7.2 Phase 구성

| Phase | 작업 | 기간 |
|---|---|---|
| Phase 0 | 사전 정리 — ArchUnit/통합 테스트 강화, RP API 계약 snapshot 테스트 추가 | ~1주 |
| Phase 1 | `:common` 추출 (단일 server 안에서, 앱은 1개 유지) | ~2주 |
| Phase 2 | `:admin-app` 추출 (백엔드 분리, MDS scheduler 임시 disable) | ~2주 |
| Phase 3 | `:passkey-app` 추출 + 기존 `:server` 디렉터리 제거 | ~1.5주 |
| Phase 4 | Admin SPA 통합 (`admin/` → `admin-ui/`, Gradle Node Plugin) | ~1주 |
| Phase 5 | MDS 옵션 B 전환 (Oracle 공유 저장소 + Redis pub/sub) | ~1.5주 |
| Phase 6 | examples/sample-rp 작성 + 문서·CI 최종 정리 | ~0.5주 |
| **합계** | | **~9-10주 (병행 가능 시 7-8주)** |

### 7.3 Phase 0 — 사전 정리

**목표**: 마이그레이션 시작 전 회귀 감지 능력 강화.

- 현재 ArchUnit 규칙 점검·강화
- 통합 테스트 커버리지 확인, end-to-end 시나리오 1-2개 추가
- **외부 API 계약 snapshot 테스트 추가** — `/api/v1/rp/**`의 요청·응답 JSON shape을 snapshot으로 고정 (`tests/contract/RpApiContractTest.java`)
- 현재 의존성 그래프 시각화로 잠재 순환 의존 색출

**완료 기준**: 기존 `./gradlew check` 전부 통과, RP 계약 테스트 깨질 수 있는 시나리오에서 실제로 깨지는지 확인.

### 7.4 Phase 1 — `:common` 추출

**목표**: 빌드 그래프 도입. 앱은 여전히 1개, Spring Boot 메인 클래스 분리 안 함.

- `settings.gradle.kts` 도입, `include(":common", ":server")`
- `:common` build.gradle.kts (`java-library` plugin)
- 의존 트리 leaf부터 순차 이동:
  - 1주차: `common/**`, `tenant/**`, `infrastructure/**`, `audit/domain/**`, `audit/repository/**`
  - 2주차: `auth/jwt/domain/**`, `auth/jwt/repository/**` (read), `MdsBlobRefreshedEvent`, `fido2/mds/**` (파서)
- 새 ArchUnit 규칙: `:common`이 admin/passkey 도메인 import 금지

**완료 기준**: `./gradlew :common:check`, `:server:check` 통과. `:server:bootRun`으로 기존 앱 동일 동작. `:common` 안에 admin/passkey import 0개.

**Rollback**: settings.gradle.kts에서 `:common` 제거, `common/src/**`를 `server/src/**`로 복사 후 디렉터리 삭제. 1-2시간.

### 7.5 Phase 2 — `:admin-app` 추출

**목표**: Admin 백엔드만 별도 Spring Boot 앱으로 분리. Passkey는 아직 `:server`에.

- 새 subproject `:admin-app` 등록 (spring-boot plugin, 포트 8081)
- admin 패키지 이동:
  - `server/admin/**` → `admin-app/`
  - `server/audit/controller/**`, `AuditChainScheduler` → admin-app
  - `MdsRefreshScheduler`, `MdsRevocationScanService`, `MdsRevocationScanListener` → admin-app
  - `RefreshTokenCleanupScheduler` → admin-app
- `AdminSecurityConfig` 이관 (4-chain → 3-chain)

**중요한 임시 처리 (Phase 2-4 동안의 MDS 동작)**:

Phase 2에서 `MdsRefreshScheduler`를 admin-app으로 옮기지만 옵션 B 전환은 Phase 5. 그 사이 admin-app은 Passkey의 `MdsBlobProvider.refresh()`를 직접 호출할 방법이 없음 (다른 JVM, S2S 미구현). MDS가 멈추지 않도록 다음 게이트 전략 사용:

| Property | Phase 2-4 값 | Phase 5+ 값 | 동작 |
|---|---|---|---|
| `passkey.mds.admin-publish` (admin-app) | `false` (기본) | `true` | admin-app의 `MdsRefreshScheduler` 활성 여부 |
| `passkey.mds.legacy-scheduler` (passkey 측) | `true` | `false` | `:server`/`:passkey-app`의 `LegacyMdsRefreshScheduler` 활성 여부 |

Phase 2 작업에서 `:server`에 `LegacyMdsRefreshScheduler` 복사본을 추가 — 기존 `MdsBlobProvider.refresh()`를 호출하는 cron. 이게 Phase 2-4 동안 MDS 갱신 책임을 짐. admin-app의 `MdsRefreshScheduler`는 옮겨져 있지만 비활성 상태로 대기.

Phase 5에서 두 property를 동시에 토글하고 `LegacyMdsRefreshScheduler` 코드 삭제.

**완료 기준**: `:admin-app:bootRun`, `:server:bootRun` 각자 단독 기동 가능. 두 앱 동시 기동 시 기존 e2e 통과. 각자 Docker 이미지 빌드 성공.

**Rollback**: admin-app 디렉터리 제거, 코드 :server로 복원. 반나절~1일.

### 7.6 Phase 3 — `:passkey-app` 추출 + `:server` 제거

**목표**: 나머지 RP·Passkey 코드를 `:passkey-app`으로 옮기고 `:server` 디렉터리 삭제.

- 새 subproject `:passkey-app` 등록 (포트 8080 — 기존 :server와 동일)
- 코드 이동:
  - `server/credential/controller/**` (RP API) → passkey-app
  - `server/credential/service/**` → passkey-app
  - `server/credential/metadata/**` (Phase 2의 LegacyMdsRefreshScheduler 포함) → passkey-app
  - `server/fido2/runtime/**` → passkey-app
  - `server/auth/apikey/**` → passkey-app
  - `server/auth/jwt/JwksController`, `JwtConfig`, `TokenService` → passkey-app
  - `server/ratelimit/**` → passkey-app
- `:passkey-app` SecurityConfig 작성
- `:server` 디렉터리 삭제 (별도 커밋)

**완료 기준**: `:server` 디렉터리 미존재. `:passkey-app:bootRun` 단독 기동. `/api/v1/rp/**`이 분리 전과 100% 동일 응답 (Phase 0 contract 테스트 검증). SDK 변경 없이 동작.

**Rollback**: `:server` 디렉터리 git revert로 복원, `:passkey-app` 제거. 반나절.

### 7.7 Phase 4 — Admin SPA 통합

**목표**: `admin/` → `admin-ui/` rename + `:admin-app`이 정적 자산 서빙.

- `admin/` → `admin-ui/` (git mv)
- `admin/Dockerfile`, `admin/nginx.conf` 삭제
- `:admin-app/build.gradle.kts`에 `com.github.node-gradle.node` 추가
- `buildSpa` task 정의 — `admin-ui`에서 `npm ci && npm run build`
- `admin-ui/dist/**` → `:admin-app/build/resources/main/static/**` 복사
- `:admin-app`에 `SpaForwardController` 추가
- 운영 배포 manifest 갱신 (nginx 컨테이너 제거)
- 운영 profile은 same-origin, local profile만 5173→8081 cross-origin 허용

**완료 기준**: `:admin-app:bootJar`이 SPA 포함 fat JAR 생성. `:admin-app` 단독 실행 시 `http://localhost:8081/`에서 SPA 로드. SPA HMR 개발 가능 (`npm run dev` + admin-app 별도 기동). Playwright e2e 통과.

**Rollback**: nginx 컨테이너 복원, `admin-ui/` → `admin/` rename, Node plugin·SpaForwardController 제거. 반나절.

### 7.8 Phase 5 — MDS 옵션 B 전환

**목표**: 사용자가 처음 말씀하신 두 번째 목표 달성 — 스케줄 Admin 단독 소유, Passkey 다중화 대응.

- DB 마이그레이션 `V<n>__mds_blob_cache.sql` (섹션 5.4)
- `:common` 신규 코드: `MdsBlobStore`, `MdsBlobRecord`, `MdsBlobSerde`
- `:admin-app` Publisher 구현:
  - `MdsBlobPublisher` (fetch + 검증 + DB insert + Redis publish)
  - `MdsRefreshScheduler`를 `@ConditionalOnProperty(passkey.mds.admin-publish=true)`로 재활성화
  - `AdminMdsController` (수동 트리거, 상태 조회)
  - SPA에 "MDS 즉시 refresh" 버튼 추가
- `:passkey-app` Subscriber 구현:
  - `MdsBlobSubscriber` (`ApplicationReadyEvent` 초기 read + Redis listener)
  - 기존 `MdsBlobProvider`를 `@ConditionalOnProperty(passkey.mds.legacy-provider=true)`로 게이트 (기본 false)
  - `RedisMessageListenerContainer` 채널 등록
- Phase 2의 `LegacyMdsRefreshScheduler` 삭제

**Cutover 절차**:
- 새 버전 배포 시 admin-app과 passkey-app을 같은 시점에 배포
- Admin 첫 publish까지 Passkey 캐시 비어있는 상태 → strict tenant 일시적 `MDS_UNAVAILABLE`
- **운영 cutover 직전**: Admin 수동 트리거 1회 또는 admin-app의 `ApplicationReadyEvent` listener가 부팅 시 1회 publish

**완료 기준**: Admin publish → DB row + Redis 이벤트 → 모든 Passkey 인스턴스가 수 초 내 새 version으로 캐시 교체. 인스턴스 1대 재시작 시 부팅 초기 read로 정상 회복. Admin 수동 트리거 audit log 기록. Redis 일시 다운 후 수동 재트리거로 회복. strict tenant attestation 신/구 BLOB에서 일관.

**Rollback**: `passkey.mds.legacy-provider=true` + Passkey 재시작 → 기존 fetch 모델로 즉시 복귀. Legacy 코드 삭제는 안정화 1-2주 후로 미룸.

### 7.9 Phase 6 — examples/sample-rp + 문서·CI 정리

**목표**: 정리 + 문서 갱신.

- `examples/sample-rp/` 생성 — SDK를 사용하는 샘플 서버, settings.gradle.kts 미포함
- `examples/sample-rp/README.md`: "납품 산출물 아님" 명시
- `CLAUDE.md` 갱신: 디렉터리 표, 기동 명령, ArchUnit 규칙, MDS 플로우
- `docs/architecture.md` 갱신: 섹션 3 그림 반영, §10 변경 이력 entry
- `docs/deployment.md` 갱신: 두 Docker 이미지 배포 절차, `mds_blob_cache` 정리 포함
- `README.md` 새 디렉터리 구조
- CI: 두 앱 병렬 빌드, Docker 이미지 2개 tag·push, admin-ui npm 캐시 추가

**완료 기준**: `examples/sample-rp/`가 SDK로 `:passkey-app`을 호출하여 등록·인증 ceremony 성공. 모든 문서 일관된 새 구조 반영. CI에서 두 앱 빌드·테스트·이미지 푸시 자동화.

### 7.10 호환성 유지 보증

마이그레이션 전 과정에서 **고객사 RP가 부르는 외부 API** 100% 호환:

| 항목 | 보장 |
|---|---|
| URL prefix `/api/v1/rp/**` | Phase 3 이후에도 그대로 |
| 요청 JSON 스키마 | 변경 없음 (Phase 0 contract 테스트 강제) |
| 응답 JSON 스키마 (ApiResponse envelope) | 변경 없음 |
| X-API-Key 헤더 인증 | 변경 없음 |
| ErrorCode 값 | 변경 없음 |
| JWKS 엔드포인트 `/.well-known/jwks.json` | 변경 없음 |
| `sdk/`, `sdk-java/` 메이저 버전 | 변경 없음 |
| 기동 포트 8080 | `:passkey-app`이 그대로 사용 |

### 7.11 위험 요소와 대응

| 위험 | 대응 |
|---|---|
| Phase 2의 MDS scheduler 임시 disable로 Phase 5까지 MDS BLOB 갱신 안 됨 | Phase 2-5 사이에 운영 배포 시 `:server` legacy scheduler 살려둠. 진짜 운영은 Phase 5 완료 후. |
| Phase 3에서 `:server` 제거 후 회귀 발견 | Phase 0 contract 테스트가 보호망. revert 한 번에 복원. |
| Phase 5 MDS 옵션 B 전환 직후 strict tenant 일시적 `MDS_UNAVAILABLE` | 배포 직전 Admin 수동 트리거 1회 또는 부팅 시 자동 publish. 운영 절차 명시. |
| 두 앱 동시 운영의 K8s/Docker 부담 증가 | Phase 4까지 dev-up.sh가 자동화. 운영 인프라는 별도 PR. |
| `:common` 비대화 | Phase 1 끝에서 코드 줄 수 점검. 800줄 넘으면 다음 Phase에서 추가 분할. |

## 8. 성공 기준 (Definition of Done)

본 spec의 구현이 완료된 상태:

- [ ] `settings.gradle.kts`에 `:common`, `:admin-app`, `:passkey-app` 3개 subproject 등록
- [ ] `:server` 디렉터리 미존재
- [ ] `admin/` → `admin-ui/` rename, `admin-ui/Dockerfile`·`nginx.conf` 미존재
- [ ] `:admin-app:bootRun`이 SPA + admin API 모두 서빙 (포트 8081)
- [ ] `:passkey-app:bootRun`이 RP API 서빙 (포트 8080)
- [ ] `:admin-app`이 cron으로 MDS BLOB을 `mds_blob_cache`에 publish
- [ ] `:passkey-app` N대가 Redis pub/sub로 새 BLOB 수신, 모두 동일 `mds.blob.cache.version` 메트릭 보고
- [ ] 고객사 SDK (`sdk/`, `sdk-java/`) 변경 없이 동작
- [ ] `/api/v1/rp/**` contract 테스트 100% 통과
- [ ] ArchUnit 규칙이 `@Scheduled`를 `:admin-app`에만 허용 강제
- [ ] DB 권한 모델: `APP_RUNTIME`이 `mds_blob_cache` INSERT 시도 시 거부
- [ ] Docker 이미지 2개 (`passkey-admin`, `passkey-core`) 빌드·태그·푸시 자동화
- [ ] `examples/sample-rp/`가 SDK로 등록·인증 ceremony 성공
- [ ] CLAUDE.md, architecture.md, deployment.md, README.md 새 구조 반영

## 9. 다음 단계

본 spec 승인 후 `writing-plans` 스킬로 Phase별 상세 구현 계획 작성. 각 Phase는 별도 PR로 들어가며, Phase 0부터 순차 진행.
