# MDS 사후 검증 기반 Credential 자동 차단 설계

- 작성일: 2026-05-23
- 작업 위치: `com.crosscert.passkey.credential.metadata` (신규 컴포넌트 3종) + 기존 도메인 확장
- 관련 마일스톤: FIDO2 core Milestone B 완료 후속 — strict 경로가 자체 코어로 통일된 상태에서 MDS 결과를 사후 적용

## 1. 배경과 문제

현재 MDS(FIDO Metadata Service) 검증은 **등록(Registration) 시점에만** 동작한다. `MdsBlobProvider`가 매일 04:00 BLOB을 다시 받지만, 이미 발급된 Credential에는 영향이 없다.

발생할 수 있는 운영 시나리오:

- MDS BLOB가 특정 AAGUID를 `REVOKED` 또는 `ATTESTATION_KEY_COMPROMISE`로 분류한다.
- 해당 AAGUID로 이전에 등록된 Credential은 그대로 인증(Assertion)을 통과한다.
- 사고 대응 절차상 운영자가 영향 사용자/기기를 식별·차단할 수단이 없다.

이 설계는 **MDS BLOB 갱신 직후 사후 재평가 → 영향 Credential 일괄 차단**을 자동화한다.

## 2. 비목표

- MDS BLOB 자체의 fetch/parse/검증 흐름은 변경하지 않는다 (`MdsBlobProvider`/`MetadataBlob` 기존 코드 그대로).
- 자동 unsuspend는 도입하지 않는다 (Platform Operator 수동 복구만).
- 외부 알림 채널(webhook/email)은 본 설계 범위 밖. Audit + 로그 + 메트릭으로 가시화.
- Registration 시점 MDS 차단 로직은 그대로 유지 (이미 정착돼 있음).

## 3. 결정 사항 요약

| 항목 | 결정 |
|---|---|
| 기본 처분 | 자동 `SUSPENDED` (REVOKED와 분리, 복구 가능) |
| 정책 범위 | 플랫폼 일괄 (테넌트별 opt-out 없음) |
| 평가 시점 | `MdsBlobProvider.refresh()` 직후 in-line 이벤트 트리거 |
| 실행 데이터소스 | `adminDataSource`(APP_ADMIN, EXEMPT) 단일 UPDATE 묶음 |
| 복구 권한 | `PLATFORM_OPERATOR` 수동 unsuspend 만, 자동 복구 없음 |
| 알림 | Audit + structured log + Micrometer 메트릭만 |
| RP UX | 전용 ErrorCode `CREDENTIAL_SUSPENDED` (C040, 403) + `CredentialView.status` 노출 + `allowCredentials` 제외 + 사용자 자체 삭제 허용 |

## 4. 아키텍처 한눈에

```
MdsBlobProvider.refresh()
  ├─ trustAnchorSource.set(...)                  # 기존
  └─ events.publishEvent(MdsBlobRefreshedEvent)  # 신규
            │
            ▼
MdsRevocationScanListener  (@Async, audit-async-executor 재사용)
  └─ MdsRevocationScanService.scan(blob)
       ├─ criticalAaguids = blob.entries.filter(isRevoked)
       ├─ [adminTx-1] CredentialAdminWriter.suspendByAaguids(...)
       ├─ [adminTx-2] RefreshTokenAdminWriter.revokeAllByTenantUserIds(...)
       ├─ per-tenant audit row (CREDENTIAL_AUTO_SUSPENDED)
       └─ metrics
```

핵심:
1. **scan은 refresh 트랜잭션 밖** — refresh 실패/scan 실패가 서로 막지 않음.
2. **단일 admin UPDATE 묶음** — VPD bypass 데이터소스로 cross-tenant 일괄 처리.
3. **이벤트 인터페이스로 의존 단방향** — `MdsBlobProvider`는 credential 도메인을 import하지 않음.
4. **수동 trigger 재사용** — `POST /api/v1/admin/mds/scan` 또는 `/_diag/mds-scan`이 같은 service 호출.

## 5. 데이터 모델

### 5.1 Flyway 마이그레이션 `V<n>__credential_suspended_status.sql`

```sql
-- (1) status enum 확장
ALTER TABLE credential DROP CONSTRAINT credential_status_chk;
ALTER TABLE credential ADD CONSTRAINT credential_status_chk
  CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED'));

-- (2) suspended 메타데이터 컬럼
ALTER TABLE credential ADD (
  suspended_at      TIMESTAMP(6) WITH TIME ZONE NULL,
  suspended_reason  VARCHAR2(64)                NULL,
  unsuspended_at    TIMESTAMP(6) WITH TIME ZONE NULL,
  unsuspended_by    VARCHAR2(128)               NULL
);

-- (3) scan 쿼리 최적화
CREATE INDEX ix_credential_aaguid_status ON credential (aaguid, status);
```

### 5.2 도메인 enum

```java
public enum CredentialStatus { ACTIVE, SUSPENDED, REVOKED }

public enum CredentialSuspendedReason {
  /** MDS BLOB 스캔에서 critical AAGUID 발견 — 본 설계의 유일 트리거(MVP). */
  MDS_REVOKED
}
```

DB의 `suspended_reason`은 `'MDS_REVOKED:'||<StatusReport name>` 형태로 저장 — enum은 카테고리, 콜론 뒤가 detail.

### 5.3 도메인 메서드 (Credential.java)

```java
public void suspend(String reasonDetail);   // ACTIVE → SUSPENDED, REVOKED 상태에서 호출 시 예외
public void unsuspend(String actorId);      // SUSPENDED → ACTIVE, 그 외 상태에서 호출 시 예외
public boolean isSuspended();
```

- bulk scan 경로는 JPA를 거치지 않고 `JdbcTemplate`로 직접 UPDATE — invariant는 DB CHECK + Java 도메인 양쪽이 강제.
- `unsuspend` 시 `suspended_at`/`suspended_reason`은 보존 (history 유지).

### 5.4 ErrorCode·AuditEventType

```java
CREDENTIAL_SUSPENDED       ("C040", HttpStatus.FORBIDDEN, "Credential is suspended"),
CREDENTIAL_INVALID_STATE   ("C041", HttpStatus.CONFLICT,  "Credential state transition not allowed"),

// AuditEventType
CREDENTIAL_AUTO_SUSPENDED,
CREDENTIAL_UNSUSPENDED,
```

Audit row payload: `{aaguidsAffected: [...], credentialsAffected: <count>, mdsBlobSerial: <n>}` — per-tenant 1 row (수천 건 per-credential audit은 SHA-256 hash chain 비용 폭증을 피함).

## 6. 컴포넌트 분해

### 6.1 패키지 배치

```
com.crosscert.passkey.credential
 ├─ metadata/
 │   ├─ MdsBlobProvider.java           [수정]   - 이벤트 발행 1줄
 │   ├─ MdsBlobRefreshedEvent.java     [신규]   - record
 │   ├─ MdsRevocationScanListener.java [신규]   - @Async 진입
 │   └─ MdsRevocationScanService.java  [신규]   - 핵심 로직
 ├─ repository/
 │   └─ CredentialAdminWriter.java     [신규]   - adminDataSource 위 JDBC
 ├─ service/
 │   └─ CredentialLifecycleService.java[수정]   - unsuspend() 추가
 └─ controller/
     └─ AdminCredentialController.java [수정]   - POST /admin/credentials/{id}/unsuspend
```

### 6.2 핵심 컴포넌트

#### `MdsBlobRefreshedEvent`
```java
public record MdsBlobRefreshedEvent(MetadataBlob blob, Instant refreshedAt) {}
```

#### `MdsBlobProvider.refresh()` 변경 (1줄 추가)
```java
events.publishEvent(new MdsBlobRefreshedEvent(blob, Instant.now()));
```
`publishEvent`는 `synchronized` 블록 안에서 호출되지만 listener가 `@Async`라 즉시 위임. refresh의 lock hold time은 그대로.

#### `MdsRevocationScanListener`
```java
@Component
@ConditionalOnBean(MdsBlobProvider.class)
public class MdsRevocationScanListener {
  @Async(AuditAsyncConfig.EXECUTOR_BEAN)
  @EventListener
  public void onBlobRefreshed(MdsBlobRefreshedEvent event) {
    try { scanService.scan(event.blob()); }
    catch (Exception e) {
      log.error("mds.revocation.scan.failed reason={}", e.getMessage(), e);
    }
  }
}
```
audit-async-executor를 재사용 — scan 빈도가 낮아 starvation 위험 미미.

#### `MdsRevocationScanService.scan(MetadataBlob)`
1. `Map<UUID, StatusReport> criticalAaguids = blob.entries.filter(isRevoked)`.
2. `credentialAdminWriter.suspendByAaguids(criticalAaguids, blob.serialNumber())` — 신규 SUSPENDED 목록 반환.
3. (5.2 보강) `tenantUserIds = newlySuspended ∪ tenantUserIdsWithSuspendedCredentialAndLiveToken()` — F5 잔존 cleanup.
4. `refreshTokenAdminWriter.revokeAllByTenantUserIds(tenantUserIds, CREDENTIAL_SUSPENDED)`.
5. per-tenant audit: `TenantContextHolder.set` → `auditService.append(CREDENTIAL_AUTO_SUSPENDED, SYSTEM, ...)` → `clear()` (try/finally).
6. 메트릭: `mds_scan_suspended_total`, `mds_scan_suspended{aaguid,reason}`, `mds_scan_tokens_revoked_total`, `mds_scan_critical_aaguids` Gauge.

#### `CredentialAdminWriter` (신규)
`@Qualifier("adminNamedJdbcTemplate")` + `@Transactional("adminTransactionManager")`.

```sql
-- (1) targets 식별 + lock
SELECT id, tenant_id, tenant_user_id, aaguid
  FROM credential
 WHERE status = 'ACTIVE' AND aaguid IN (:aaguids)
   FOR UPDATE;

-- (2) batch UPDATE (status guard로 동시성 안전)
UPDATE credential
   SET status = 'SUSPENDED',
       suspended_at = SYS_EXTRACT_UTC(SYSTIMESTAMP),
       suspended_reason = :reason
 WHERE id = :id AND status = 'ACTIVE';
```

- Oracle multi-row RETURNING이 plain JDBC에서 안 되므로 SELECT-then-UPDATE 패턴.
- `IN (:aaguids)` Oracle 1000개 한계 — 실제 critical AAGUID는 수십 미만. 안전망으로 청크 처리는 future work.

#### `RefreshTokenAdminWriter` (신규)
```sql
UPDATE refresh_token
   SET revoked_at = SYS_EXTRACT_UTC(SYSTIMESTAMP),
       revoked_reason = :reason
 WHERE revoked_at IS NULL AND tenant_user_id IN (:ids);
```

#### `CredentialLifecycleService.unsuspend(credentialId, actorId)` (수정)
JPA 단건 — `c.unsuspend(actorId)` 도메인 메서드 사용. Audit: `CREDENTIAL_UNSUSPENDED` with `{previousReason}`. **refresh token 자동 재발급 없음** — 사용자가 다시 ceremony 거쳐 받음.

#### `AdminCredentialController.unsuspend` (수정)
```java
@PostMapping("/credentials/{credentialId}/unsuspend")
@PreAuthorize("hasRole('PLATFORM_OPERATOR')")
```
`RP_ADMIN`은 403.

#### `AuthenticationService` 분기 (수정)
`findByCredentialId` 결과의 `status == SUSPENDED` → `CREDENTIAL_SUSPENDED` throw. `REVOKED`는 기존 흐름.

#### `AuthenticationOptionsBuilder` (수정)
`allowCredentials` 구성 시 `status == ACTIVE`만 포함 — SUSPENDED/REVOKED 모두 제외.

## 7. 데이터 흐름

### 7.1 정상 cron 경로
```
Scheduler → refresh() → publishEvent → @Async listener
   → scan: criticalAaguids → SELECT FOR UPDATE → batch UPDATE
   → refresh_token bulk revoke
   → per-tenant audit + metrics
```

### 7.2 SUSPENDED credential 인증 시도
```
verifyAssertion → findByCredentialId → status==SUSPENDED
  → audit AUTHENTICATION_REJECTED
  → throw CREDENTIAL_SUSPENDED (403 C040)
```
RP는 사용자에게 "기기 일시 차단" 메시지 표시. 정상 흐름에선 `allowCredentials`에서 제외되어 거의 도달하지 않음 — 도달은 (a) 사용자가 직접 ID 제출 또는 (b) options 조회와 assertion 사이 scan 들어옴 (동시성 윈도) 케이스.

### 7.3 PO 수동 unsuspend
```
POST /api/v1/admin/credentials/{id}/unsuspend
  → @PreAuthorize hasRole(PLATFORM_OPERATOR)
  → c.unsuspend(actorId) (SUSPENDED 외 상태 → CREDENTIAL_INVALID_STATE 409)
  → audit CREDENTIAL_UNSUSPENDED {previousReason}
```

### 7.4 트랜잭션·일관성

| 단계 | 트랜잭션 | 실패 시 |
|---|---|---|
| (1) credential UPDATE | adminTx (분리) | 롤백, 다음 scan에서 재시도 |
| (2) refresh_token UPDATE | adminTx (별도) | fail-toward-blocked (credential은 이미 SUSPENDED), 5.2 보강이 다음 cycle에서 청소 |
| (3) per-tenant audit | tenant context + default tx | 기존 AsyncAuditWriter 정책 따름 |

**(1)+(2) 분리 이유**: (a) refresh_token 실패 → credential 복원이 되면 fail-toward-blocked 깨짐, (b) lock hold time 분리.

### 7.5 동시성

- `MdsBlobProvider.refresh()` `synchronized` — refresh 직렬화.
- `SELECT ... FOR UPDATE` + status guard — 동시 scan 안전.
- 사용자 ceremony vs scan — `FOR UPDATE` lock으로 직렬화. 기본 무한 wait (필요시 `WAIT 10`).

### 7.6 idempotency / 재실행

- 같은 BLOB 두 번 scan → 두 번째 0행 affected.
- BLOB의 critical이 사라진 AAGUID → 자동 복구 없음 (PO 수동만).
- 수동 trigger: `POST /api/v1/admin/mds/scan` 또는 `/_diag/mds-scan`이 `mdsBlobProvider.lastBlob`을 재사용.

## 8. 에러 처리·관측성

### 8.1 실패 분류

| # | 지점 | 영향 | 처리 | 자동 회복 |
|---|---|---|---|---|
| F1 | refresh() HTTP/parse 실패 | 이벤트 미발행 | 기존 fail-soft | 다음 cron |
| F2 | publish 후 JVM 중단 | scan 누락 | — | 다음 cron / manual |
| F3 | scan() unchecked 예외 | 부분 적용 가능 | listener catch + 로그 | 다음 cron |
| F4 | credential UPDATE 트랜잭션 실패 | SUSPENDED 0건 | 롤백 → 예외 → catch | 다음 cron (idempotent) |
| F5 | credential 성공 후 token UPDATE 실패 | credential SUSPENDED, 일부 token 잔존 | 로그/메트릭. fail-toward-blocked | 5.2 보강이 다음 cycle에서 cleanup |
| F6 | audit 실패 | 운영자 view 누락 | 기존 AsyncAuditWriter 정책 | 기존 인프라 |
| F7 | unsuspend on non-SUSPENDED | 409 응답 | CREDENTIAL_INVALID_STATE | 사용자 행위 |
| F8 | SUSPENDED로 assertion | 403 응답 | CREDENTIAL_SUSPENDED + audit | — |

### 8.2 F5 보강 (idempotency)

scan 진입 시마다 `tenantUserIdsWithSuspendedCredentialAndLiveToken()` 쿼리로 lingering token 청소:
```sql
SELECT DISTINCT c.tenant_user_id
  FROM credential c
  JOIN refresh_token t ON t.tenant_user_id = c.tenant_user_id
 WHERE c.status = 'SUSPENDED' AND t.revoked_at IS NULL;
```
이 집합과 newly-suspended의 합집합을 token revoke 대상으로.

### 8.3 ErrorCode·HTTP 매핑

| Code | Class | HTTP | 사용처 |
|---|---|---|---|
| `CREDENTIAL_SUSPENDED` | C040 | 403 | assertion 시 SUSPENDED 발견 |
| `CREDENTIAL_INVALID_STATE` | C041 | 409 | unsuspend가 잘못된 상태에 시도 |

### 8.4 Structured 로그

```
mds.scan.start critical=12 blobSerial=4711
mds.scan.suspended.applied affected=87 aaguidGroups=8 elapsedMs=143
mds.scan.tokens.revoked count=64 users=42
mds.scan.audit.appended tenants=23
mds.scan.done credentials=87 tokens=64 tenants=23 blobSerial=4711 elapsedMs=312
mds.revocation.scan.failed stage=credential_update reason=...
credential.unsuspend tenantId=... credentialDbId=... actor=...
credential.assertion.rejected.suspended tenantId=... credentialDbId=...
```

### 8.5 Micrometer 메트릭

| 메트릭 | 타입 | 태그 |
|---|---|---|
| `mds_scan_runs_total` | Counter | `outcome={success,failure}` |
| `mds_scan_duration_seconds` | Timer | — |
| `mds_scan_suspended_total` | Counter | — |
| `mds_scan_suspended` | Counter | `aaguid`, `reason` |
| `mds_scan_tokens_revoked_total` | Counter | — |
| `mds_scan_critical_aaguids` | Gauge | — |
| `credential_assertion_rejected` | Counter | `reason="suspended"` (기존 확장) |
| `credential_unsuspend_total` | Counter | — |

`aaguid` 태그 cardinality는 critical AAGUID 한정 (~수십). 안전망으로 cardinality 한계 모니터링.

### 8.6 운영 runbook

`docs/`에 짧은 페이지 추가:
1. `mds_scan_runs_total{outcome="failure"}` 증가 → `mds.revocation.scan.failed stage=...` 확인.
2. credential 단계 실패 → DB lock/ORA-error.
3. token 단계 실패 → 다음 cycle 자동 cleanup; 즉시 회복은 `POST /_diag/mds-scan`.
4. AAGUID 영향 범위 → admin audit 검색 `event_type=CREDENTIAL_AUTO_SUSPENDED AND payload.aaguidsAffected CONTAINS '<aaguid>'`.
5. PO 결정 → `POST /api/v1/admin/credentials/{id}/unsuspend`.

## 9. 테스트 전략

### 9.1 Unit (~20)
- `CredentialTest`: suspend/unsuspend invariant, 멱등, history 보존.
- `MdsRevocationScanServiceTest` (Mockito): critical 추출, F5 보강, audit/메트릭 호출, 빈 입력.
- `MdsRevocationScanListenerTest`: 정상 위임, 예외 catch, sync executor override.

### 9.2 Slice (~10)
- `CredentialAdminWriterIntegrationTest` (`@JdbcTest`): suspendByAaguids — status guard, 멱등, FOR UPDATE lock, `tenantUserIdsWithSuspendedCredentialAndLiveToken`.
- `RefreshTokenAdminWriterIntegrationTest`: 빈 입력 guard, 멱등.
- `V<n>__credential_suspended_status` Flyway 검증 + CHECK constraint + 인덱스 존재.

### 9.3 Integration (~7) — `AdminEnabledIntegrationTestBase` 패턴
- `MdsScanIntegrationTest`: 두 tenant cross-tenant end-to-end (BLOB fixture → SUSPENDED + token revoke + audit + 메트릭). Awaitility로 `@Async` 대기.
- `MdsScanRetryIntegrationTest`: §5.2 lingering token cleanup.
- `AssertionWithSuspendedCredentialIntegrationTest`: 403 C040.
- `AuthenticationOptionsExcludesSuspendedTest`: allowCredentials에 SUSPENDED 미포함.
- `AdminUnsuspendIntegrationTest`: PO 성공, RP_ADMIN 403, non-SUSPENDED에 409.
- `MdsScanRpClientApiContractTest`: `CredentialView` JSON에 `status`/`suspendedAt`/`suspendedReason` 노출.

### 9.4 ArchUnit 추가
```java
// metadata 패키지는 admin 패키지를 의존하지 않음 (cron 독립성)
noClasses().that().resideInAPackage("..credential.metadata..")
    .should().dependOnClassesThat().resideInAPackage("..admin..");
```

### 9.5 보안 회귀 테스트
- bulk UPDATE가 admin DS 외 경로로 동작하지 않는지 (오버라이드로 0건 affected 검증).
- listener 진입 스레드가 `audit-async-*`인지 (sync 회귀 방지).
- SUSPENDED 상태가 IDOR 시나리오에서 다른 user에게 노출 위험 없는지.

### 9.6 Fixture
기존 `MdsBlobFixtureBuilder`에 `withRevokedAaguid(UUID)`/`withCompromisedAaguid(UUID)` 추가 (BouncyCastle JWT 빌드 재사용).

### 9.7 의도된 누락
- 부하 테스트 (수만 건 SUSPEND). MVP는 수백~수천 가정 — Phase 2.
- MDS 서버 다운: 기존 refresh 실패 테스트 커버.

## 10. 변경 영향 요약

| 영역 | 변경 |
|---|---|
| Flyway | 신규 `V<n>__credential_suspended_status.sql` |
| 도메인 | `CredentialStatus.SUSPENDED` 추가, `Credential.suspend/unsuspend`, `CredentialSuspendedReason` enum |
| 신규 컴포넌트 | `MdsBlobRefreshedEvent`, `MdsRevocationScanListener`, `MdsRevocationScanService`, `CredentialAdminWriter`, `RefreshTokenAdminWriter` |
| 수정 | `MdsBlobProvider`(이벤트 발행 1줄), `CredentialLifecycleService.unsuspend`, `AdminCredentialController.unsuspend`, `AuthenticationService` 분기, `AuthenticationOptionsBuilder` 필터 |
| API | 신규 `POST /api/v1/admin/credentials/{id}/unsuspend`, 신규 `POST /api/v1/admin/mds/scan` 또는 `/_diag/mds-scan`, `CredentialView` JSON에 `status`/`suspendedAt`/`suspendedReason` 필드 |
| ErrorCode | `CREDENTIAL_SUSPENDED` (C040, 403), `CREDENTIAL_INVALID_STATE` (C041, 409) |
| Audit | `CREDENTIAL_AUTO_SUSPENDED`, `CREDENTIAL_UNSUSPENDED` |
| 메트릭 | `mds_scan_*` 6종 + `credential_assertion_rejected{reason="suspended"}` 확장 + `credential_unsuspend_total` |
| 문서 | `architecture.md` §X 추가 (사후 MDS 차단 흐름 한 줄 다이어그램), `docs/runbook-mds-scan.md` 신규 |

## 11. 미해결 / 합의 필요 (구현 단계 진입 전 재확인)

본 설계 작성 시점에 결정하지 않고 구현 단계에서 검증할 항목:

1. **`FOR UPDATE` lock wait 정책** — 무한 vs `WAIT 10`. 기존 코드에 정착된 패턴 확인.
2. **수동 trigger endpoint 위치** — `/_diag/mds-scan` vs `/api/v1/admin/mds/scan`. production LB `/_diag` 차단 여부에 따라 둘 다 두는 안전 선택지 고려.
3. **`AuthenticationOptionsBuilder` 현재 status 필터 상태** — REVOKED는 이미 제외되는지 점검 후 SUSPENDED 합류.
4. **`AsyncAuditWriter` retry/dead-letter 정책** — F6에서 의존하는 동작이 실제로 어떻게 정의돼 있는지 확인.
5. **`audit-async-executor` ThreadPool 용량** — scan 큰 cycle이 audit과 풀을 공유할 때 부담 검증. 별도 풀 분리는 Phase 2 옵션.

## 12. 향후 확장 (본 설계 범위 밖)

- 자동 unsuspend (MDS critical 제거 감지 시) — silent restoration 위험 검토 후.
- `SUSPENDED` 사유 카테고리 추가 (`SIGNATURE_COUNTER_REGRESSION_AUTO`, `ADMIN_TEMPORARY_BLOCK` 등).
- 외부 알림 (RP webhook, email).
- bulk unsuspend (실수 방지 위해 의도적으로 미제공).
- AAGUID `IN` 청크 처리 (현재 ~수십 가정).
