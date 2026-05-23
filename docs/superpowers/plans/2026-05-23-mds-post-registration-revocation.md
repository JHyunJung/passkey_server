# MDS Post-Registration Credential Revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** MDS BLOB 갱신 직후 critical AAGUID(`REVOKED`/`ATTESTATION_KEY_COMPROMISE` 등)에 해당하는 Credential을 자동으로 `SUSPENDED`로 차단하고, Platform Operator만 수동 unsuspend할 수 있는 사후 검증 파이프라인 구축.

**Architecture:** `MdsBlobProvider.refresh()`가 `MdsBlobRefreshedEvent`를 발행 → `@Async` listener가 audit-executor 스레드에서 `MdsRevocationScanService.scan(blob)`을 호출 → `adminDataSource`(APP_ADMIN, EXEMPT) 위의 단일 `SELECT FOR UPDATE` + batch `UPDATE`로 cross-tenant 일괄 처리 → tenant context 빌려 per-tenant audit row → Micrometer 메트릭. 자동 복구 없음, PO 수동 unsuspend 만 허용.

**Tech Stack:** Spring Boot 3.5, Java 17, Oracle 19c VPD, Hibernate JPA, `NamedParameterJdbcTemplate`(adminDataSource), `@Async`(`auditExecutor`), Micrometer, Awaitility(테스트), BouncyCastle(MDS fixture).

**Spec:** `docs/superpowers/specs/2026-05-23-mds-post-registration-revocation-design.md`

**Branch:** `worktree-mds-post-revocation` (worktree: `.claude/worktrees/mds-post-revocation`)

---

## File Structure

### 신규 파일

| 경로 | 책임 |
|---|---|
| `server/src/main/resources/db/migration/V2__credential_suspended_status.sql` | status enum 확장 + suspended 메타데이터 컬럼 + 인덱스 |
| `server/src/main/java/com/crosscert/passkey/credential/domain/CredentialSuspendedReason.java` | suspended reason 카테고리 enum |
| `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobRefreshedEvent.java` | record event |
| `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanListener.java` | `@Async @EventListener` 진입점 |
| `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanService.java` | scan 핵심 로직 |
| `server/src/main/java/com/crosscert/passkey/credential/repository/CredentialAdminWriter.java` | adminDataSource bulk UPDATE |
| `server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenAdminWriter.java` | adminDataSource bulk token revoke |
| `server/src/test/java/com/crosscert/passkey/unit/credential/domain/CredentialSuspendInvariantTest.java` | 도메인 invariant |
| `server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanServiceTest.java` | scan 로직 unit |
| `server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanListenerTest.java` | listener 위임·예외 catch |
| `server/src/test/java/com/crosscert/passkey/slice/credential/CredentialAdminWriterSliceTest.java` | `@JdbcTest` writer SQL |
| `server/src/test/java/com/crosscert/passkey/slice/auth/RefreshTokenAdminWriterSliceTest.java` | `@JdbcTest` writer SQL |
| `server/src/test/java/com/crosscert/passkey/integration/credential/MdsScanIntegrationTest.java` | end-to-end scan 흐름 |
| `server/src/test/java/com/crosscert/passkey/integration/credential/MdsScanRetryIntegrationTest.java` | F5 lingering token cleanup |
| `server/src/test/java/com/crosscert/passkey/integration/credential/AssertionWithSuspendedCredentialIntegrationTest.java` | 403 P016 assertion |
| `server/src/test/java/com/crosscert/passkey/integration/credential/AuthenticationOptionsExcludesSuspendedTest.java` | allowCredentials 필터 |
| `server/src/test/java/com/crosscert/passkey/integration/credential/AdminUnsuspendIntegrationTest.java` | PO 성공 / RP_ADMIN 403 / 잘못된 state 409 |

### 수정 파일

| 경로 | 변경 |
|---|---|
| `server/src/main/java/com/crosscert/passkey/credential/domain/CredentialStatus.java` | `SUSPENDED` enum 값 추가 |
| `server/src/main/java/com/crosscert/passkey/credential/domain/Credential.java` | 컬럼/필드 + `suspend()`/`unsuspend()`/`isSuspended()` |
| `server/src/main/java/com/crosscert/passkey/credential/api/CredentialView.java` | `suspendedAt`/`suspendedReason` 필드 |
| `server/src/main/java/com/crosscert/passkey/common/exception/ErrorCode.java` | `CREDENTIAL_SUSPENDED`(P016), `CREDENTIAL_INVALID_STATE`(P017) |
| `server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java` | `CREDENTIAL_AUTO_SUSPENDED`, `CREDENTIAL_UNSUSPENDED` |
| `server/src/main/java/com/crosscert/passkey/auth/jwt/domain/RevokedReason.java` | `CREDENTIAL_SUSPENDED` 값 추가 |
| `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobProvider.java` | `ApplicationEventPublisher` 주입 + `publishEvent` 1줄 |
| `server/src/main/java/com/crosscert/passkey/credential/service/CredentialLifecycleService.java` | `unsuspend(credentialId, actorId)` 추가 |
| `server/src/main/java/com/crosscert/passkey/credential/service/AuthenticationService.java` | SUSPENDED 분기 → `CREDENTIAL_SUSPENDED` throw |
| `server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java` | `findAllActiveByTenantUserId` 필터 / allowCredentials용 |
| `server/src/main/java/com/crosscert/passkey/admin/controller/AdminCredentialController.java` | `POST .../credentials/{id}/unsuspend` 추가 |
| `server/src/main/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java` | ArchUnit 규칙 1건 추가 |

> 참고: AdminCredentialController는 `/api/v1/admin/tenants/{tenantId}/credentials` 패턴이므로 신규 endpoint는 `POST /api/v1/admin/tenants/{tenantId}/credentials/{credentialId}/unsuspend`로 합류.

---

## Implementation Order

**Foundation → Bulk path → Single-credential path → Wiring → End-to-end.**

| # | Task | 의존 |
|---|---|---|
| 1 | DB 마이그레이션 + ck_cred_status 확장 | — |
| 2 | `CredentialStatus.SUSPENDED` + 도메인 메서드 + JPA 컬럼 매핑 | 1 |
| 3 | `CredentialSuspendedReason` enum | — |
| 4 | `ErrorCode` 2건 + `AuditEventType` 2건 + `RevokedReason.CREDENTIAL_SUSPENDED` | — |
| 5 | `CredentialView` 필드 확장 | 2 |
| 6 | `CredentialAdminWriter` (bulk SELECT-FOR-UPDATE + batch UPDATE + lingering token query) | 1 |
| 7 | `RefreshTokenAdminWriter` (bulk token revoke) | 4 |
| 8 | `MdsRevocationScanService` (scan 핵심) | 2,4,6,7 |
| 9 | `MdsBlobRefreshedEvent` + `MdsBlobProvider` 이벤트 발행 + `MdsRevocationScanListener` | 8 |
| 10 | `AuthenticationService` SUSPENDED 분기 + allowCredentials 필터링 | 2,4 |
| 11 | `CredentialLifecycleService.unsuspend` + `AdminCredentialController` endpoint | 2,4 |
| 12 | Integration tests (end-to-end, retry, assertion 거부, options 필터, admin unsuspend) | 8,9,10,11 |
| 13 | ArchUnit 규칙 + 최종 `./gradlew check` | 12 |

각 task는 **Red → Green → Commit** 사이클을 따른다.

---

## Task 1: Flyway 마이그레이션 — credential SUSPENDED 컬럼 + 인덱스

**Files:**
- Create: `server/src/main/resources/db/migration/V2__credential_suspended_status.sql`

- [ ] **Step 1.1: 마이그레이션 작성**

`server/src/main/resources/db/migration/V2__credential_suspended_status.sql`:

```sql
-- V2: Add SUSPENDED status to credential lifecycle (MDS post-registration revocation).
-- See docs/superpowers/specs/2026-05-23-mds-post-registration-revocation-design.md §5.

-- (1) Replace status CHECK to allow SUSPENDED. ACTIVE/REVOKED unchanged.
ALTER TABLE credential DROP CONSTRAINT ck_cred_status;
ALTER TABLE credential ADD CONSTRAINT ck_cred_status
  CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED'));

-- (2) Suspended metadata columns (nullable — non-SUSPENDED rows leave them NULL).
ALTER TABLE credential ADD (
  suspended_at      TIMESTAMP(6) WITH TIME ZONE NULL,
  suspended_reason  VARCHAR2(64)                NULL,
  unsuspended_at    TIMESTAMP(6) WITH TIME ZONE NULL,
  unsuspended_by    VARCHAR2(128)               NULL
);

-- (3) Index for "find ACTIVE rows by AAGUID" scan path.
-- aaguid is sparse (most rows non-null), status is enum-cardinality 3.
-- Tenant_id intentionally omitted: APP_ADMIN scans cross-tenant.
CREATE INDEX ix_credential_aaguid_status ON credential (aaguid, status);
```

- [ ] **Step 1.2: 로컬 DB reset 후 적용 확인**

Run:
```bash
docker compose up -d
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
cd server && ./gradlew bootRun --args='--spring.profiles.active=local' &
# 부팅 후 Ctrl+C, Flyway가 V2까지 적용됐는지 확인
```

Expected: 로그에 `Successfully applied migration: V2__credential_suspended_status.sql`.

수동 검증:
```bash
docker exec passkey-oracle sqlplus -L -S APP_MIGRATOR/change_me_migrator@//localhost:1521/FREEPDB1 \
  -c "SELECT search_condition FROM user_constraints WHERE constraint_name = 'CK_CRED_STATUS'"
```
Expected: `status IN ('ACTIVE','SUSPENDED','REVOKED')`.

- [ ] **Step 1.3: 커밋**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/mds-post-revocation
git add server/src/main/resources/db/migration/V2__credential_suspended_status.sql
git commit -m "feat(db): V2 add SUSPENDED status + suspended metadata to credential

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: CredentialStatus.SUSPENDED + Credential 도메인 메서드

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/domain/CredentialStatus.java`
- Modify: `server/src/main/java/com/crosscert/passkey/credential/domain/Credential.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/credential/domain/CredentialSuspendInvariantTest.java`

- [ ] **Step 2.1: 실패 테스트 작성**

`server/src/test/java/com/crosscert/passkey/unit/credential/domain/CredentialSuspendInvariantTest.java`:

```java
package com.crosscert.passkey.unit.credential.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CredentialSuspendInvariantTest {

  private Credential newCredential() {
    return Credential.create(
        UUID.randomUUID(),
        UUID.randomUUID(),
        "cred-id-base64url",
        new byte[] {1, 2, 3},
        UUID.randomUUID(),
        "internal",
        "user-handle",
        0L,
        false,
        false);
  }

  @Test
  void suspend_active_transitionsToSuspended_andRecordsReason() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.SUSPENDED);
    assertThat(c.getSuspendedAt()).isNotNull();
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
    assertThat(c.isSuspended()).isTrue();
    assertThat(c.isActive()).isFalse();
  }

  @Test
  void suspend_isIdempotent() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    var firstAt = c.getSuspendedAt();
    c.suspend("MDS_REVOKED:USER_VERIFICATION_BYPASS"); // no-op
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.SUSPENDED);
    assertThat(c.getSuspendedAt()).isEqualTo(firstAt);
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
  }

  @Test
  void suspend_onRevoked_throwsInvalidState() {
    Credential c = newCredential();
    c.revoke();
    assertThatThrownBy(() -> c.suspend("MDS_REVOKED:REVOKED"))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.CREDENTIAL_INVALID_STATE);
  }

  @Test
  void unsuspend_suspendedToActive_recordsActorAndPreservesHistory() {
    Credential c = newCredential();
    c.suspend("MDS_REVOKED:REVOKED");
    var suspAt = c.getSuspendedAt();
    c.unsuspend("admin-uuid");
    assertThat(c.getStatus()).isEqualTo(CredentialStatus.ACTIVE);
    assertThat(c.getUnsuspendedAt()).isNotNull();
    assertThat(c.getUnsuspendedBy()).isEqualTo("admin-uuid");
    // history preserved
    assertThat(c.getSuspendedAt()).isEqualTo(suspAt);
    assertThat(c.getSuspendedReason()).isEqualTo("MDS_REVOKED:REVOKED");
  }

  @Test
  void unsuspend_onActive_throwsInvalidState() {
    Credential c = newCredential();
    assertThatThrownBy(() -> c.unsuspend("admin"))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.CREDENTIAL_INVALID_STATE);
  }

  @Test
  void unsuspend_onRevoked_throwsInvalidState() {
    Credential c = newCredential();
    c.revoke();
    assertThatThrownBy(() -> c.unsuspend("admin"))
        .isInstanceOf(BusinessException.class)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.CREDENTIAL_INVALID_STATE);
  }
}
```

- [ ] **Step 2.2: 컴파일 실패 확인**

Run: `cd server && ./gradlew compileTestJava 2>&1 | tail -20`

Expected: `cannot find symbol: method suspend(String)`, `getSuspendedAt()`, `CredentialStatus.SUSPENDED`, `ErrorCode.CREDENTIAL_INVALID_STATE` 등.

- [ ] **Step 2.3: `CredentialStatus`에 `SUSPENDED` 추가**

`server/src/main/java/com/crosscert/passkey/credential/domain/CredentialStatus.java`:

```java
package com.crosscert.passkey.credential.domain;

public enum CredentialStatus {
  ACTIVE,
  /** Post-registration auto-block (e.g. MDS critical AAGUID). Recoverable via PO unsuspend. */
  SUSPENDED,
  REVOKED
}
```

- [ ] **Step 2.4: `Credential` 엔티티에 필드·메서드 추가**

`Credential.java`의 기존 필드 블록 (`revokedReason` 다음) 에 추가:

```java
  @Column(name = "suspended_at")
  private OffsetDateTime suspendedAt;

  @Column(name = "suspended_reason", length = 64)
  private String suspendedReason;

  @Column(name = "unsuspended_at")
  private OffsetDateTime unsuspendedAt;

  @Column(name = "unsuspended_by", length = 128)
  private String unsuspendedBy;
```

`revoke(CredentialRevokedReason)` 메서드 다음에 추가:

```java
  /**
   * Suspend (post-registration auto-block path — currently MDS critical AAGUID detection).
   * Idempotent: re-suspending preserves the original suspendedAt/Reason.
   * Throws CREDENTIAL_INVALID_STATE on REVOKED credential (revoked is terminal).
   */
  public void suspend(String reasonDetail) {
    if (this.status == CredentialStatus.SUSPENDED) {
      return; // idempotent — keep original metadata
    }
    if (this.status == CredentialStatus.REVOKED) {
      throw new BusinessException(
          ErrorCode.CREDENTIAL_INVALID_STATE, "cannot suspend a revoked credential");
    }
    this.status = CredentialStatus.SUSPENDED;
    this.suspendedAt = OffsetDateTime.now(ZoneOffset.UTC);
    this.suspendedReason = reasonDetail;
  }

  /**
   * Platform Operator manual unsuspend. Restores ACTIVE; preserves suspendedAt/Reason for
   * forensics. Throws CREDENTIAL_INVALID_STATE on non-SUSPENDED state.
   */
  public void unsuspend(String actorId) {
    if (this.status != CredentialStatus.SUSPENDED) {
      throw new BusinessException(
          ErrorCode.CREDENTIAL_INVALID_STATE, "credential is not suspended");
    }
    this.status = CredentialStatus.ACTIVE;
    this.unsuspendedAt = OffsetDateTime.now(ZoneOffset.UTC);
    this.unsuspendedBy = actorId;
  }

  public boolean isSuspended() {
    return this.status == CredentialStatus.SUSPENDED;
  }
```

> 참고: `BusinessException`·`ErrorCode`는 이미 import되어 있다. `ErrorCode.CREDENTIAL_INVALID_STATE`는 Task 4에서 추가하므로 컴파일은 Task 4 이후 통과한다. Task 4를 먼저 시작해도 무방하나, 이 plan 순서로 진행하려면 Task 2.4 마지막에 Task 4의 ErrorCode 두 줄 추가를 함께 수행한다.

- [ ] **Step 2.5: 테스트 실행 (Task 4 완료 후)**

Task 4 (ErrorCode 추가) 완료 후:

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.domain.CredentialSuspendInvariantTest"`

Expected: 6/6 passing.

- [ ] **Step 2.6: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/domain/CredentialStatus.java \
        server/src/main/java/com/crosscert/passkey/credential/domain/Credential.java \
        server/src/test/java/com/crosscert/passkey/unit/credential/domain/CredentialSuspendInvariantTest.java
git commit -m "feat(credential): add SUSPENDED status + suspend/unsuspend domain methods

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: CredentialSuspendedReason enum

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/credential/domain/CredentialSuspendedReason.java`

- [ ] **Step 3.1: enum 작성**

```java
package com.crosscert.passkey.credential.domain;

/**
 * Why a credential was auto-suspended. The DB column {@code credential.suspended_reason} holds
 * {@code <category>:<detail>} (e.g. {@code "MDS_REVOKED:ATTESTATION_KEY_COMPROMISE"}). This enum
 * is the category — the detail varies per category (MDS StatusReport name, etc.).
 *
 * <p>Single value at MVP; reserved as a category space for future suspension triggers
 * (signature-counter regression auto, admin temporary block).
 */
public enum CredentialSuspendedReason {
  /** Detected during {@code MdsRevocationScanService.scan} — AAGUID critical in current BLOB. */
  MDS_REVOKED
}
```

- [ ] **Step 3.2: 컴파일 확인**

Run: `cd server && ./gradlew compileJava`

Expected: BUILD SUCCESSFUL.

- [ ] **Step 3.3: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/domain/CredentialSuspendedReason.java
git commit -m "feat(credential): add CredentialSuspendedReason enum category

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: ErrorCode / AuditEventType / RevokedReason 확장

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/common/exception/ErrorCode.java`
- Modify: `server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java`
- Modify: `server/src/main/java/com/crosscert/passkey/auth/jwt/domain/RevokedReason.java`

- [ ] **Step 4.1: `ErrorCode` 2건 추가**

`ErrorCode.java`의 `MDS_REFRESH_FAILED(... "P015" ...)` 다음 줄에 추가:

```java
  CREDENTIAL_SUSPENDED(HttpStatus.FORBIDDEN, "P016", "Credential is suspended"),
  CREDENTIAL_INVALID_STATE(HttpStatus.CONFLICT, "P017", "Credential state transition not allowed"),
```

- [ ] **Step 4.2: `AuditEventType` 2건 추가**

`AuditEventType.java`의 `// ---------- CREDENTIAL_LIFECYCLE ----------` 그룹 안 `ATTESTATION_TRUST_FAILED` 다음에 추가:

```java
  CREDENTIAL_AUTO_SUSPENDED,
  CREDENTIAL_UNSUSPENDED,
```

- [ ] **Step 4.3: `RevokedReason` 추가**

`RevokedReason.java`의 `ADMIN_FORCED` 다음에 추가:

```java
  /** Underlying credential was auto-suspended by MDS revocation scan. */
  CREDENTIAL_SUSPENDED,
```

- [ ] **Step 4.4: 컴파일 확인**

Run: `cd server && ./gradlew compileJava compileTestJava`

Expected: BUILD SUCCESSFUL.

- [ ] **Step 4.5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/common/exception/ErrorCode.java \
        server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java \
        server/src/main/java/com/crosscert/passkey/auth/jwt/domain/RevokedReason.java
git commit -m "feat(error): add CREDENTIAL_SUSPENDED/INVALID_STATE codes + audit/revoke reasons

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

이 시점에 Task 2의 테스트를 다시 실행 — 컴파일·테스트 모두 통과해야 함:

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.domain.CredentialSuspendInvariantTest"`

Expected: 6/6 passing.

---

## Task 5: CredentialView에 suspended 필드 노출

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/api/CredentialView.java`

- [ ] **Step 5.1: record 시그니처 + factory 확장**

`CredentialView.java` 전체 교체:

```java
package com.crosscert.passkey.credential.api;

import com.crosscert.passkey.credential.domain.Credential;
import java.time.OffsetDateTime;
import java.util.UUID;

public record CredentialView(
    UUID id,
    UUID tenantUserId,
    String credentialId,
    String nickname,
    String status,
    String aaguid,
    String transports,
    long signatureCounter,
    OffsetDateTime lastUsedAt,
    OffsetDateTime createdAt,
    OffsetDateTime revokedAt,
    String revokedReason,
    OffsetDateTime suspendedAt,
    String suspendedReason,
    OffsetDateTime unsuspendedAt,
    String unsuspendedBy) {

  public static CredentialView from(Credential c) {
    return new CredentialView(
        c.getId(),
        c.getTenantUserId(),
        c.getCredentialId(),
        c.getNickname(),
        c.getStatus().name(),
        c.getAaguid() == null ? null : c.getAaguid().toString(),
        c.getTransports(),
        c.getSignatureCounter(),
        c.getLastUsedAt(),
        c.getCreatedAt(),
        c.getRevokedAt(),
        c.getRevokedReason() == null ? null : c.getRevokedReason().name(),
        c.getSuspendedAt(),
        c.getSuspendedReason(),
        c.getUnsuspendedAt(),
        c.getUnsuspendedBy());
  }
}
```

- [ ] **Step 5.2: 컴파일 확인**

Run: `cd server && ./gradlew compileJava compileTestJava`

Expected: BUILD SUCCESSFUL.

- [ ] **Step 5.3: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/api/CredentialView.java
git commit -m "feat(api): expose suspended fields on CredentialView

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: CredentialAdminWriter — bulk SELECT-FOR-UPDATE + batch UPDATE

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/credential/repository/CredentialAdminWriter.java`
- Test: `server/src/test/java/com/crosscert/passkey/slice/credential/CredentialAdminWriterSliceTest.java`

- [ ] **Step 6.1: 실패 테스트 작성**

`server/src/test/java/com/crosscert/passkey/slice/credential/CredentialAdminWriterSliceTest.java`:

```java
package com.crosscert.passkey.slice.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.repository.CredentialAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter.SuspendedRow;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.infrastructure.datasource.AdminJdbcConfig;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@JdbcTest
@ActiveProfiles("integration")
@TestPropertySource(properties = "passkey.admin.enabled=true")
@Import({AdminJdbcConfig.class, CredentialAdminWriter.class})
class CredentialAdminWriterSliceTest {

  @Autowired private CredentialAdminWriter writer;

  @Autowired
  @Qualifier("adminJdbcTemplate")
  private NamedParameterJdbcTemplate admin;

  private UUID tenantA;
  private UUID userA;
  private UUID aaguid1;
  private UUID aaguid2;

  @BeforeEach
  void seed() {
    tenantA = UUID.randomUUID();
    userA = UUID.randomUUID();
    aaguid1 = UUID.randomUUID();
    aaguid2 = UUID.randomUUID();
    // assume base rows for tenant + user are present from baseline migration test fixture;
    // if not, this test will create them via direct INSERT. (See SliceTest base helper.)
    // Production slice harness pattern: insert tenant+user rows directly here.
    insertTenantUserMinimal(tenantA, userA);
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid1, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid1, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid2, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid2, "REVOKED");
  }

  @Test
  void suspendByAaguids_onlyAffectsActiveRowsInGivenAaguids() {
    List<SuspendedRow> result =
        writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4711L);
    assertThat(result).hasSize(2);
    // verify DB state
    Integer suspended = admin.queryForObject(
        "SELECT COUNT(*) FROM credential WHERE aaguid = HEXTORAW(:a) AND status = 'SUSPENDED'",
        new MapSqlParameterSource("a", HexFormat.of().formatHex(uuidBytes(aaguid1))),
        Integer.class);
    assertThat(suspended).isEqualTo(2);
    // aaguid2 unaffected
    Integer otherSuspended = admin.queryForObject(
        "SELECT COUNT(*) FROM credential WHERE aaguid = HEXTORAW(:a) AND status = 'SUSPENDED'",
        new MapSqlParameterSource("a", HexFormat.of().formatHex(uuidBytes(aaguid2))),
        Integer.class);
    assertThat(otherSuspended).isZero();
  }

  @Test
  void suspendByAaguids_isIdempotent() {
    writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4711L);
    List<SuspendedRow> second =
        writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4712L);
    assertThat(second).isEmpty(); // already SUSPENDED → SELECT WHERE status='ACTIVE' returns 0
  }

  @Test
  void suspendByAaguids_emptyInput_returnsEmpty_andRunsNoSql() {
    assertThat(writer.suspendByAaguids(Map.of(), 4711L)).isEmpty();
  }

  @Test
  void tenantUserIdsWithSuspendedCredentialAndLiveToken_findsLingering() {
    // Suspend aaguid1 credentials
    writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4711L);
    // Insert a live refresh_token for userA
    insertLiveRefreshToken(tenantA, userA);
    Set<UUID> users = writer.tenantUserIdsWithSuspendedCredentialAndLiveToken();
    assertThat(users).contains(userA);
  }

  // ---- helpers ----
  private byte[] uuidBytes(UUID u) {
    java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(16);
    b.putLong(u.getMostSignificantBits());
    b.putLong(u.getLeastSignificantBits());
    return b.array();
  }

  private void insertTenantUserMinimal(UUID tenantId, UUID userId) {
    admin.update(
        "INSERT INTO tenant (id, slug, name, status, created_at, updated_at) "
      + "VALUES (HEXTORAW(:tid), :slug, :name, 'ACTIVE', SYSTIMESTAMP, SYSTIMESTAMP)",
        new MapSqlParameterSource()
            .addValue("tid", HexFormat.of().formatHex(uuidBytes(tenantId)))
            .addValue("slug", "t-" + tenantId.toString().substring(0, 8))
            .addValue("name", "test"));
    admin.update(
        "INSERT INTO tenant_user (id, tenant_id, external_id, created_at, updated_at) "
      + "VALUES (HEXTORAW(:uid), HEXTORAW(:tid), :ext, SYSTIMESTAMP, SYSTIMESTAMP)",
        new MapSqlParameterSource()
            .addValue("uid", HexFormat.of().formatHex(uuidBytes(userId)))
            .addValue("tid", HexFormat.of().formatHex(uuidBytes(tenantId)))
            .addValue("ext", "ext-" + userId.toString().substring(0, 8)));
  }

  private void insertCredential(UUID id, UUID tenantId, UUID userId, UUID aaguid, String status) {
    admin.update(
        "INSERT INTO credential (id, tenant_id, tenant_user_id, credential_id, "
      + "public_key_cose, aaguid, user_handle, signature_counter, backup_eligible, "
      + "backup_state, status, created_at, updated_at) VALUES ("
      + "HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, HEXTORAW('010203'), "
      + "HEXTORAW(:agid), :uh, 0, 0, 0, :st, SYSTIMESTAMP, SYSTIMESTAMP)",
        new MapSqlParameterSource()
            .addValue("id", HexFormat.of().formatHex(uuidBytes(id)))
            .addValue("tid", HexFormat.of().formatHex(uuidBytes(tenantId)))
            .addValue("uid", HexFormat.of().formatHex(uuidBytes(userId)))
            .addValue("cid", "credId-" + id.toString().substring(0, 8))
            .addValue("agid", HexFormat.of().formatHex(uuidBytes(aaguid)))
            .addValue("uh", "uhandle-" + userId.toString().substring(0, 8))
            .addValue("st", status));
  }

  private void insertLiveRefreshToken(UUID tenantId, UUID userId) {
    admin.update(
        "INSERT INTO refresh_token (id, tenant_id, tenant_user_id, issued_at, expires_at, "
      + "created_at, updated_at) VALUES ("
      + "HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), SYSTIMESTAMP, "
      + "SYSTIMESTAMP + INTERVAL '7' DAY, SYSTIMESTAMP, SYSTIMESTAMP)",
        new MapSqlParameterSource()
            .addValue("id", HexFormat.of().formatHex(uuidBytes(UUID.randomUUID())))
            .addValue("tid", HexFormat.of().formatHex(uuidBytes(tenantId)))
            .addValue("uid", HexFormat.of().formatHex(uuidBytes(userId))));
  }
}
```

- [ ] **Step 6.2: 컴파일 실패 확인**

Run: `cd server && ./gradlew compileTestJava 2>&1 | tail -15`

Expected: `cannot find symbol: class CredentialAdminWriter`.

- [ ] **Step 6.3: `CredentialAdminWriter` 구현**

`server/src/main/java/com/crosscert/passkey/credential/repository/CredentialAdminWriter.java`:

```java
package com.crosscert.passkey.credential.repository;

import com.crosscert.passkey.fido2.mds.StatusReport;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bulk credential writes that VPD predicates would otherwise block. Runs on the {@code APP_ADMIN}
 * (EXEMPT) data source so SUSPEND can span tenants in a single UPDATE.
 *
 * <p>Used by {@code MdsRevocationScanService} for the post-registration MDS revocation pipeline.
 * The corresponding single-credential / per-tenant lifecycle path stays on {@code
 * CredentialLifecycleService} + JPA.
 */
@Slf4j
@Component
@ConditionalOnBean(name = "adminJdbcTemplate")
@RequiredArgsConstructor
public class CredentialAdminWriter {

  @Qualifier("adminJdbcTemplate")
  private final NamedParameterJdbcTemplate admin;

  /** Identification tuple returned from {@link #suspendByAaguids}. */
  public record SuspendedRow(UUID id, UUID tenantId, UUID tenantUserId, UUID aaguid) {}

  /**
   * Suspend all {@code ACTIVE} credentials whose AAGUID is in {@code aaguids.keySet()}.
   *
   * <p>Two-step pattern (Oracle multi-row RETURNING isn't supported on plain JDBC):
   *
   * <ol>
   *   <li>{@code SELECT ... FOR UPDATE} to lock target rows and collect their identifiers.
   *   <li>{@code UPDATE ... WHERE id=? AND status='ACTIVE'} as a batch, status guard for safety.
   * </ol>
   *
   * @return the rows that transitioned ACTIVE → SUSPENDED (empty if none).
   */
  @Transactional("adminTransactionManager")
  public List<SuspendedRow> suspendByAaguids(
      Map<UUID, StatusReport> aaguids, long mdsBlobSerial) {
    if (aaguids == null || aaguids.isEmpty()) {
      return List.of();
    }
    List<String> aaguidHex =
        aaguids.keySet().stream().map(this::uuidToHex).toList();

    List<SuspendedRow> targets =
        admin.query(
            "SELECT id, tenant_id, tenant_user_id, aaguid "
                + "  FROM credential "
                + " WHERE status = 'ACTIVE' "
                + "   AND aaguid IN (SELECT HEXTORAW(column_value) FROM TABLE(:aaguids)) "
                + "   FOR UPDATE",
            new MapSqlParameterSource("aaguids", aaguidHex),
            (rs, n) ->
                new SuspendedRow(
                    uuidFromBytes(rs.getBytes("id")),
                    uuidFromBytes(rs.getBytes("tenant_id")),
                    uuidFromBytes(rs.getBytes("tenant_user_id")),
                    uuidFromBytes(rs.getBytes("aaguid"))));

    if (targets.isEmpty()) {
      log.info("mds.scan.suspend.nothingToDo aaguids={} blobSerial={}", aaguids.size(), mdsBlobSerial);
      return targets;
    }

    SqlParameterSource[] batch =
        targets.stream()
            .map(
                r ->
                    new MapSqlParameterSource()
                        .addValue("id", uuidToHex(r.id()))
                        .addValue(
                            "reason",
                            "MDS_REVOKED:" + aaguids.get(r.aaguid()).name()))
            .toArray(SqlParameterSource[]::new);

    int[] affected =
        admin.batchUpdate(
            "UPDATE credential "
                + "   SET status = 'SUSPENDED', "
                + "       suspended_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), "
                + "       suspended_reason = :reason, "
                + "       updated_at = SYSTIMESTAMP "
                + " WHERE id = HEXTORAW(:id) AND status = 'ACTIVE'",
            batch);

    int total = 0;
    for (int a : affected) total += a;
    log.info(
        "mds.scan.suspend.applied targets={} affected={} blobSerial={}",
        targets.size(),
        total,
        mdsBlobSerial);
    return targets;
  }

  /**
   * Distinct {@code tenant_user_id}s that have ≥1 SUSPENDED credential AND ≥1 unrevoked refresh
   * token. Used by scan §5.2 boost to clean up tokens that survived an earlier F5 (token revoke
   * failure after credential SUSPENDED succeeded).
   */
  @Transactional("adminTransactionManager")
  public Set<UUID> tenantUserIdsWithSuspendedCredentialAndLiveToken() {
    List<byte[]> raws =
        admin.query(
            "SELECT DISTINCT c.tenant_user_id "
                + "  FROM credential c "
                + "  JOIN refresh_token t ON t.tenant_user_id = c.tenant_user_id "
                + " WHERE c.status = 'SUSPENDED' AND t.revoked_at IS NULL",
            (rs, n) -> rs.getBytes(1));
    java.util.LinkedHashSet<UUID> out = new java.util.LinkedHashSet<>();
    for (byte[] b : raws) out.add(uuidFromBytes(b));
    return out;
  }

  // ---- helpers ----
  private String uuidToHex(UUID u) {
    return HexFormat.of().formatHex(uuidBytes(u));
  }

  private static byte[] uuidBytes(UUID u) {
    ByteBuffer b = ByteBuffer.allocate(16);
    b.putLong(u.getMostSignificantBits());
    b.putLong(u.getLeastSignificantBits());
    return b.array();
  }

  private static UUID uuidFromBytes(byte[] raw) {
    ByteBuffer bb = ByteBuffer.wrap(raw);
    long high = bb.getLong();
    long low = bb.getLong();
    return new UUID(high, low);
  }
}
```

> **참고**: `IN (SELECT HEXTORAW(column_value) FROM TABLE(:aaguids))`는 Spring `NamedParameterJdbcTemplate`의 list expansion이 RAW(16) 비교에서 직접 동작하지 않기 때문에 사용. 표준 패턴이지만 환경에 따라 `oracle.sql.STRUCT` array bind로 교체 가능. **만약 위 패턴이 ORA-에러를 내면**, fallback으로 청크 처리:
> ```java
> // fallback: build IN list manually
> StringBuilder in = new StringBuilder();
> for (int i = 0; i < aaguidHex.size(); i++) {
>   if (i > 0) in.append(",");
>   in.append("HEXTORAW(:a").append(i).append(")");
> }
> // bind each a0..aN individually
> ```

- [ ] **Step 6.4: Slice 테스트 실행**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.credential.CredentialAdminWriterSliceTest"`

Expected: 4/4 passing. If `TABLE(:aaguids)` ORA-error 발생 시 fallback 패턴으로 교체 후 재실행.

- [ ] **Step 6.5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/repository/CredentialAdminWriter.java \
        server/src/test/java/com/crosscert/passkey/slice/credential/CredentialAdminWriterSliceTest.java
git commit -m "feat(credential): CredentialAdminWriter for bulk SUSPEND on adminDataSource

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: RefreshTokenAdminWriter — bulk token revoke

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenAdminWriter.java`
- Test: `server/src/test/java/com/crosscert/passkey/slice/auth/RefreshTokenAdminWriterSliceTest.java`

- [ ] **Step 7.1: 실패 테스트 작성**

`server/src/test/java/com/crosscert/passkey/slice/auth/RefreshTokenAdminWriterSliceTest.java`:

```java
package com.crosscert.passkey.slice.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenAdminWriter;
import com.crosscert.passkey.infrastructure.datasource.AdminJdbcConfig;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@JdbcTest
@ActiveProfiles("integration")
@TestPropertySource(properties = "passkey.admin.enabled=true")
@Import({AdminJdbcConfig.class, RefreshTokenAdminWriter.class})
class RefreshTokenAdminWriterSliceTest {

  @Autowired private RefreshTokenAdminWriter writer;

  @Autowired
  @Qualifier("adminJdbcTemplate")
  private NamedParameterJdbcTemplate admin;

  @Test
  void revokeAllByTenantUserIds_empty_returnsZero_runsNoSql() {
    int n = writer.revokeAllByTenantUserIds(Set.of(), RevokedReason.CREDENTIAL_SUSPENDED);
    assertThat(n).isZero();
  }

  @Test
  void revokeAllByTenantUserIds_revokesOnlyLiveTokens_forSelectedUsers() {
    UUID tenantId = UUID.randomUUID();
    UUID userA = UUID.randomUUID();
    UUID userB = UUID.randomUUID();
    seedTenantUser(tenantId, userA);
    seedTenantUser(tenantId, userB);
    insertToken(tenantId, userA, null); // live
    insertToken(tenantId, userA, "ROTATED"); // already revoked
    insertToken(tenantId, userB, null); // live but not in target set
    int n = writer.revokeAllByTenantUserIds(Set.of(userA), RevokedReason.CREDENTIAL_SUSPENDED);
    assertThat(n).isEqualTo(1);
    // userB live token still live
    Integer liveOnB = admin.queryForObject(
        "SELECT COUNT(*) FROM refresh_token WHERE tenant_user_id = HEXTORAW(:u) AND revoked_at IS NULL",
        new MapSqlParameterSource("u", hex(userB)),
        Integer.class);
    assertThat(liveOnB).isEqualTo(1);
  }

  private void seedTenantUser(UUID t, UUID u) {
    admin.update(
        "INSERT INTO tenant (id, slug, name, status, created_at, updated_at) "
      + "VALUES (HEXTORAW(:t), :s, 'n', 'ACTIVE', SYSTIMESTAMP, SYSTIMESTAMP)",
        new MapSqlParameterSource().addValue("t", hex(t))
            .addValue("s", "t-" + t.toString().substring(0, 8)));
    admin.update(
        "INSERT INTO tenant_user (id, tenant_id, external_id, created_at, updated_at) "
      + "VALUES (HEXTORAW(:u), HEXTORAW(:t), :e, SYSTIMESTAMP, SYSTIMESTAMP)",
        new MapSqlParameterSource().addValue("u", hex(u)).addValue("t", hex(t))
            .addValue("e", "e-" + u.toString().substring(0, 8)));
  }

  private void insertToken(UUID t, UUID u, String revokedReason) {
    MapSqlParameterSource p = new MapSqlParameterSource()
        .addValue("id", hex(UUID.randomUUID()))
        .addValue("t", hex(t))
        .addValue("u", hex(u))
        .addValue("rr", revokedReason);
    String sql = revokedReason == null
        ? "INSERT INTO refresh_token (id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
        + "VALUES (HEXTORAW(:id), HEXTORAW(:t), HEXTORAW(:u), SYSTIMESTAMP, SYSTIMESTAMP + INTERVAL '7' DAY, SYSTIMESTAMP, SYSTIMESTAMP)"
        : "INSERT INTO refresh_token (id, tenant_id, tenant_user_id, issued_at, expires_at, revoked_at, revoked_reason, created_at, updated_at) "
        + "VALUES (HEXTORAW(:id), HEXTORAW(:t), HEXTORAW(:u), SYSTIMESTAMP, SYSTIMESTAMP + INTERVAL '7' DAY, SYSTIMESTAMP, :rr, SYSTIMESTAMP, SYSTIMESTAMP)";
    admin.update(sql, p);
  }

  private static String hex(UUID u) {
    ByteBuffer b = ByteBuffer.allocate(16);
    b.putLong(u.getMostSignificantBits());
    b.putLong(u.getLeastSignificantBits());
    return HexFormat.of().formatHex(b.array());
  }
}
```

- [ ] **Step 7.2: 컴파일 실패 확인**

Run: `cd server && ./gradlew compileTestJava 2>&1 | tail -10`

Expected: `cannot find symbol: class RefreshTokenAdminWriter`.

- [ ] **Step 7.3: `RefreshTokenAdminWriter` 구현**

`server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenAdminWriter.java`:

```java
package com.crosscert.passkey.auth.jwt.repository;

import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Cross-tenant bulk revoke of refresh tokens on the {@code APP_ADMIN} (EXEMPT) data source. Used
 * by {@code MdsRevocationScanService} to burn all live tokens of users whose credentials were
 * just SUSPENDED.
 */
@Component
@ConditionalOnBean(name = "adminJdbcTemplate")
@RequiredArgsConstructor
public class RefreshTokenAdminWriter {

  @Qualifier("adminJdbcTemplate")
  private final NamedParameterJdbcTemplate admin;

  @Transactional("adminTransactionManager")
  public int revokeAllByTenantUserIds(Set<UUID> tenantUserIds, RevokedReason reason) {
    if (tenantUserIds == null || tenantUserIds.isEmpty()) {
      return 0;
    }
    List<String> idHex = tenantUserIds.stream().map(this::hex).toList();
    return admin.update(
        "UPDATE refresh_token "
            + "   SET revoked_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), "
            + "       revoked_reason = :reason, "
            + "       updated_at = SYSTIMESTAMP "
            + " WHERE revoked_at IS NULL "
            + "   AND tenant_user_id IN (SELECT HEXTORAW(column_value) FROM TABLE(:ids))",
        new MapSqlParameterSource()
            .addValue("reason", reason.name())
            .addValue("ids", idHex));
  }

  private String hex(UUID u) {
    ByteBuffer b = ByteBuffer.allocate(16);
    b.putLong(u.getMostSignificantBits());
    b.putLong(u.getLeastSignificantBits());
    return HexFormat.of().formatHex(b.array());
  }
}
```

- [ ] **Step 7.4: Slice 테스트 실행**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.auth.RefreshTokenAdminWriterSliceTest"`

Expected: 2/2 passing.

- [ ] **Step 7.5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenAdminWriter.java \
        server/src/test/java/com/crosscert/passkey/slice/auth/RefreshTokenAdminWriterSliceTest.java
git commit -m "feat(auth): RefreshTokenAdminWriter for bulk revoke on adminDataSource

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: MdsRevocationScanService — scan 핵심 로직

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanService.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanServiceTest.java`

- [ ] **Step 8.1: 실패 테스트 작성**

`server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanServiceTest.java`:

```java
package com.crosscert.passkey.unit.credential.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenAdminWriter;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanService;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanService.ScanResult;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter.SuspendedRow;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MdsRevocationScanServiceTest {

  @Mock private CredentialAdminWriter credentialAdminWriter;
  @Mock private RefreshTokenAdminWriter refreshTokenAdminWriter;
  @Mock private AuditService auditService;
  private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
  private MdsRevocationScanService service;

  @BeforeEach
  void init() {
    service =
        new MdsRevocationScanService(
            credentialAdminWriter, refreshTokenAdminWriter, auditService, meterRegistry);
  }

  @Test
  void scan_noCriticalEntries_skipsAllWrites() {
    MetadataBlob blob = blob(4711L,
        entry(UUID.randomUUID(), StatusReport.FIDO_CERTIFIED));
    ScanResult r = service.scan(blob);
    assertThat(r.credentialsAffected()).isZero();
    verify(credentialAdminWriter, never()).suspendByAaguids(any(), eq(4711L));
    verify(refreshTokenAdminWriter, never()).revokeAllByTenantUserIds(any(), any());
    verify(auditService, never()).append(any(), any(), any(), anyString(), anyString(), any());
  }

  @Test
  void scan_criticalEntries_runFullPipeline_andAuditPerTenant() {
    UUID a1 = UUID.randomUUID();
    UUID a2 = UUID.randomUUID();
    UUID tenant1 = UUID.randomUUID();
    UUID tenant2 = UUID.randomUUID();
    UUID user1 = UUID.randomUUID();
    UUID user2 = UUID.randomUUID();
    UUID user3 = UUID.randomUUID();
    MetadataBlob blob = blob(4711L,
        entry(a1, StatusReport.REVOKED),
        entry(a2, StatusReport.ATTESTATION_KEY_COMPROMISE),
        entry(UUID.randomUUID(), StatusReport.FIDO_CERTIFIED));
    when(credentialAdminWriter.suspendByAaguids(any(), eq(4711L)))
        .thenReturn(
            List.of(
                new SuspendedRow(UUID.randomUUID(), tenant1, user1, a1),
                new SuspendedRow(UUID.randomUUID(), tenant1, user2, a1),
                new SuspendedRow(UUID.randomUUID(), tenant2, user3, a2)));
    when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken())
        .thenReturn(Set.of());
    when(refreshTokenAdminWriter.revokeAllByTenantUserIds(any(), eq(RevokedReason.CREDENTIAL_SUSPENDED)))
        .thenReturn(2);

    ScanResult r = service.scan(blob);
    assertThat(r.credentialsAffected()).isEqualTo(3);
    assertThat(r.tokensRevoked()).isEqualTo(2);
    assertThat(r.tenantsAffected()).containsExactlyInAnyOrder(tenant1, tenant2);
    // per-tenant audit row
    verify(auditService, times(1))
        .append(
            eq(AuditEventType.CREDENTIAL_AUTO_SUSPENDED),
            eq(ActorType.SYSTEM),
            eq(null),
            eq("MDS_SCAN"),
            eq("4711"),
            any());
    // tenant context set twice (one per tenant)
    verify(auditService, times(2))
        .append(any(), any(), any(), anyString(), anyString(), any());
    // metrics
    assertThat(meterRegistry.counter("mds.scan.suspended.total").count()).isEqualTo(3);
    assertThat(meterRegistry.counter("mds.scan.tokens.revoked.total").count()).isEqualTo(2);
  }

  @Test
  void scan_picksFirstCriticalReportPerEntry() {
    UUID a = UUID.randomUUID();
    // Entry with critical + non-critical mixed → service must select a critical one
    MetadataBlob blob = blob(1L, entryMulti(a, List.of(StatusReport.UPDATE_AVAILABLE, StatusReport.REVOKED)));
    when(credentialAdminWriter.suspendByAaguids(any(), eq(1L))).thenReturn(List.of());
    when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken()).thenReturn(Set.of());
    when(refreshTokenAdminWriter.revokeAllByTenantUserIds(any(), any())).thenReturn(0);
    service.scan(blob);
    verify(credentialAdminWriter).suspendByAaguids(
        argThat(m -> StatusReport.REVOKED.equals(m.get(a))), eq(1L));
  }

  // ---- helpers ----
  private static org.mockito.ArgumentMatcher<Map<UUID, StatusReport>> argMatch(
      java.util.function.Predicate<Map<UUID, StatusReport>> p) {
    return p::test;
  }

  private static org.mockito.ArgumentMatcher<Map<UUID, StatusReport>> argThat(
      java.util.function.Predicate<Map<UUID, StatusReport>> p) {
    return argMatch(p);
  }

  private static MetadataBlob blob(long serial, MetadataEntry... entries) {
    return new MetadataBlob(serial, Instant.now().plusSeconds(86400), List.of(entries));
  }

  private static MetadataEntry entry(UUID aaguid, StatusReport status) {
    return new MetadataEntry(aaguid, List.of(), List.of(status));
  }

  private static MetadataEntry entryMulti(UUID aaguid, List<StatusReport> statuses) {
    return new MetadataEntry(aaguid, List.of(), statuses);
  }
}
```

> **참고**: `MetadataBlob` 생성자 시그니처가 다를 수 있다. 코드 확인 후 `entries()` factory에 맞게 조정. 그 경우 `entry()` 헬퍼와 함께 fixture builder를 사용한다.

- [ ] **Step 8.2: 컴파일 실패 확인**

Run: `cd server && ./gradlew compileTestJava 2>&1 | tail -15`

Expected: `cannot find symbol: class MdsRevocationScanService`.

- [ ] **Step 8.3: `MdsRevocationScanService` 구현**

`server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanService.java`:

```java
package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter.SuspendedRow;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Service;

/**
 * Post-registration MDS revocation: scans an MDS BLOB for critical AAGUIDs and SUSPENDs the
 * affected credentials cross-tenant. See
 * docs/superpowers/specs/2026-05-23-mds-post-registration-revocation-design.md.
 *
 * <p>Idempotent: re-running with the same BLOB is a no-op (status guard).
 */
@Slf4j
@Service
@ConditionalOnBean(CredentialAdminWriter.class)
@RequiredArgsConstructor
public class MdsRevocationScanService {

  private final CredentialAdminWriter credentialAdminWriter;
  private final RefreshTokenAdminWriter refreshTokenAdminWriter;
  private final AuditService auditService;
  private final MeterRegistry meterRegistry;

  /** Outcome of one scan cycle. */
  public record ScanResult(
      long blobSerial, int credentialsAffected, int tokensRevoked, Set<UUID> tenantsAffected) {
    public static ScanResult empty(long blobSerial) {
      return new ScanResult(blobSerial, 0, 0, Set.of());
    }
  }

  public ScanResult scan(MetadataBlob blob) {
    Timer.Sample sample = Timer.start(meterRegistry);
    try {
      ScanResult result = doScan(blob);
      meterRegistry.counter("mds.scan.runs.total", "outcome", "success").increment();
      meterRegistry.gauge(
          "mds.scan.critical.aaguids",
          (double) countCritical(blob));
      return result;
    } catch (RuntimeException e) {
      meterRegistry.counter("mds.scan.runs.total", "outcome", "failure").increment();
      throw e;
    } finally {
      sample.stop(meterRegistry.timer("mds.scan.duration"));
    }
  }

  private ScanResult doScan(MetadataBlob blob) {
    Map<UUID, StatusReport> criticalAaguids = new LinkedHashMap<>();
    for (MetadataEntry e : blob.entries()) {
      if (e == null || e.aaguid() == null) continue;
      e.statusReports().stream()
          .filter(StatusReport::isCritical)
          .findFirst()
          .ifPresent(s -> criticalAaguids.putIfAbsent(e.aaguid(), s));
    }

    log.info(
        "mds.scan.start critical={} blobSerial={}",
        criticalAaguids.size(),
        blob.serialNumber());

    if (criticalAaguids.isEmpty()) {
      return ScanResult.empty(blob.serialNumber());
    }

    long t0 = System.currentTimeMillis();
    List<SuspendedRow> newlySuspended =
        credentialAdminWriter.suspendByAaguids(criticalAaguids, blob.serialNumber());
    log.info(
        "mds.scan.suspended.applied affected={} aaguidGroups={} elapsedMs={}",
        newlySuspended.size(),
        criticalAaguids.size(),
        System.currentTimeMillis() - t0);

    // §5.2 boost: include lingering SUSPENDED+live-token users so a previous F5 gets cleaned up.
    Set<UUID> tenantUserIds = new HashSet<>();
    for (SuspendedRow r : newlySuspended) tenantUserIds.add(r.tenantUserId());
    tenantUserIds.addAll(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken());

    int tokensRevoked =
        refreshTokenAdminWriter.revokeAllByTenantUserIds(
            tenantUserIds, RevokedReason.CREDENTIAL_SUSPENDED);
    log.info(
        "mds.scan.tokens.revoked count={} users={}", tokensRevoked, tenantUserIds.size());

    // Per-tenant audit rows.
    Map<UUID, List<SuspendedRow>> byTenant =
        newlySuspended.stream().collect(Collectors.groupingBy(SuspendedRow::tenantId));
    byTenant.forEach((tenantId, rows) -> writeAuditUnder(tenantId, rows, blob.serialNumber()));
    log.info("mds.scan.audit.appended tenants={}", byTenant.size());

    // Metrics.
    meterRegistry.counter("mds.scan.suspended.total").increment(newlySuspended.size());
    meterRegistry.counter("mds.scan.tokens.revoked.total").increment(tokensRevoked);
    Map<UUID, Long> perAaguid =
        newlySuspended.stream()
            .collect(Collectors.groupingBy(SuspendedRow::aaguid, Collectors.counting()));
    perAaguid.forEach(
        (aaguid, count) ->
            meterRegistry
                .counter(
                    "mds.scan.suspended",
                    "aaguid",
                    aaguid.toString(),
                    "reason",
                    criticalAaguids.get(aaguid).name())
                .increment(count));

    log.info(
        "mds.scan.done credentials={} tokens={} tenants={} blobSerial={}",
        newlySuspended.size(),
        tokensRevoked,
        byTenant.size(),
        blob.serialNumber());

    return new ScanResult(
        blob.serialNumber(), newlySuspended.size(), tokensRevoked, byTenant.keySet());
  }

  private void writeAuditUnder(UUID tenantId, List<SuspendedRow> rows, long blobSerial) {
    Set<String> aaguids =
        rows.stream().map(r -> r.aaguid().toString()).collect(Collectors.toCollection(java.util.LinkedHashSet::new));
    Map<String, Object> payload =
        Map.of(
            "credentialsAffected", rows.size(),
            "aaguidsAffected", aaguids,
            "mdsBlobSerial", blobSerial);
    try {
      TenantContextHolder.set(new TenantContext(tenantId, "mds-scan:" + tenantId));
      auditService.append(
          AuditEventType.CREDENTIAL_AUTO_SUSPENDED,
          ActorType.SYSTEM,
          null,
          "MDS_SCAN",
          String.valueOf(blobSerial),
          payload);
    } finally {
      TenantContextHolder.clear();
    }
  }

  private static int countCritical(MetadataBlob blob) {
    int n = 0;
    for (MetadataEntry e : blob.entries()) {
      if (e != null && e.statusReports().stream().anyMatch(StatusReport::isCritical)) n++;
    }
    return n;
  }
}
```

> **참고 — ActorType.SYSTEM 존재 여부**: 만약 ActorType enum에 `SYSTEM`이 없다면 enum에 추가하거나 기존 `ADMIN` 사용. 컴파일 단계에서 확인.

- [ ] **Step 8.4: Unit 테스트 실행**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.metadata.MdsRevocationScanServiceTest"`

Expected: 3/3 passing.

- [ ] **Step 8.5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanService.java \
        server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanServiceTest.java
git commit -m "feat(mds): MdsRevocationScanService — bulk SUSPEND + audit + metrics

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: 이벤트 발행 + Async Listener (MdsBlobProvider wire-up)

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobRefreshedEvent.java`
- Create: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanListener.java`
- Modify: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobProvider.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanListenerTest.java`

- [ ] **Step 9.1: 이벤트 record 생성**

`MdsBlobRefreshedEvent.java`:

```java
package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MetadataBlob;
import java.time.Instant;

/**
 * Published by {@link MdsBlobProvider#refresh()} after a successful BLOB fetch + verify. Consumed
 * asynchronously by {@link MdsRevocationScanListener} on the {@code auditExecutor} pool so the
 * refresh transaction does not block on cross-tenant credential UPDATEs.
 */
public record MdsBlobRefreshedEvent(MetadataBlob blob, Instant refreshedAt) {}
```

- [ ] **Step 9.2: `MdsBlobProvider` 변경**

`MdsBlobProvider.java`:

생성자에 `ApplicationEventPublisher` 주입 추가:
```java
private final ApplicationEventPublisher events;

@Autowired
public MdsBlobProvider(
    MdsProperties props,
    ResourceLoader resourceLoader,
    ApplicationEventPublisher events) {
  this.props = props;
  this.rootCa = loadRootCa(resourceLoader);
  this.restClient = RestClient.create();
  this.events = events;
  log.info(...);
}
```

`refresh()`의 `lastFetched.set(Instant.now());` 다음 줄(성공 로그 다음)에 추가:
```java
events.publishEvent(
    new MdsBlobRefreshedEvent(blob, Instant.now()));
```

> 정확한 위치는 `log.info("mds.refresh.success ...")` 다음 줄. 예외 catch 블록은 건드리지 말 것.

- [ ] **Step 9.3: Listener 실패 테스트 작성**

`MdsRevocationScanListenerTest.java`:

```java
package com.crosscert.passkey.unit.credential.metadata;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanListener;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanService;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MdsRevocationScanListenerTest {

  @Mock private MdsRevocationScanService scanService;
  @InjectMocks private MdsRevocationScanListener listener;

  @Test
  void onBlobRefreshed_delegatesToService() {
    MetadataBlob blob = new MetadataBlob(1L, Instant.now().plusSeconds(86400), List.of());
    listener.onBlobRefreshed(new MdsBlobRefreshedEvent(blob, Instant.now()));
    verify(scanService, times(1)).scan(blob);
  }

  @Test
  void onBlobRefreshed_swallowsExceptions() {
    MetadataBlob blob = new MetadataBlob(1L, Instant.now().plusSeconds(86400), List.of());
    doThrow(new RuntimeException("boom")).when(scanService).scan(any());
    // Must not throw — fail-safe contract.
    listener.onBlobRefreshed(new MdsBlobRefreshedEvent(blob, Instant.now()));
    verify(scanService).scan(blob);
  }
}
```

- [ ] **Step 9.4: Listener 구현**

`MdsRevocationScanListener.java`:

```java
package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.audit.service.AuditAsyncConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Bridges {@link MdsBlobRefreshedEvent} → {@link MdsRevocationScanService} on the {@code
 * auditExecutor} thread pool. Fail-safe: exceptions are logged but never propagated to the event
 * publisher (refresh transaction must not depend on scan outcome).
 */
@Slf4j
@Component
@ConditionalOnBean(MdsRevocationScanService.class)
@RequiredArgsConstructor
public class MdsRevocationScanListener {

  private final MdsRevocationScanService scanService;

  @Async(AuditAsyncConfig.EXECUTOR_BEAN)
  @EventListener
  public void onBlobRefreshed(MdsBlobRefreshedEvent event) {
    try {
      scanService.scan(event.blob());
    } catch (Exception e) {
      log.error(
          "mds.revocation.scan.failed blobSerial={} reason={}",
          event.blob().serialNumber(),
          e.getMessage(),
          e);
    }
  }
}
```

- [ ] **Step 9.5: 테스트 실행 + 컴파일 확인**

Run: `cd server && ./gradlew compileJava compileTestJava`

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.metadata.MdsRevocationScanListenerTest"`

Expected: 2/2 passing. + BUILD SUCCESSFUL for compile.

- [ ] **Step 9.6: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobRefreshedEvent.java \
        server/src/main/java/com/crosscert/passkey/credential/metadata/MdsRevocationScanListener.java \
        server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobProvider.java \
        server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsRevocationScanListenerTest.java
git commit -m "feat(mds): publish MdsBlobRefreshedEvent + async scan listener

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: AuthenticationService SUSPENDED 분기 + allowCredentials 필터

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/service/AuthenticationService.java`
- Modify: `server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java`

이 task는 후속 integration test(Task 12)에서 종합 검증되므로 unit test는 분기 추가만 확인하고 빠르게 진행한다.

- [ ] **Step 10.1: `CredentialRepository`에 ACTIVE-only 메서드 추가 또는 점검**

`CredentialRepository.java` 안 기존 메서드 확인:

```bash
grep -n "findAll.*TenantUserId\|findAllBy" server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java
```

이미 `findAllByTenantUserId(UUID)`가 있으면 allowCredentials 호출자에서 status 필터링.
없으면 추가:

```java
@Query("SELECT c FROM Credential c WHERE c.tenantUserId = :uid AND c.status = "
    + "com.crosscert.passkey.credential.domain.CredentialStatus.ACTIVE")
List<Credential> findAllActiveByTenantUserId(@Param("uid") UUID tenantUserId);
```

- [ ] **Step 10.2: `AuthenticationService`의 lookup 분기 수정**

`AuthenticationService.java`에서 credential을 찾는 코드(예: `verifyAssertion` 안 `findByCredentialId` 직후) 검색:

```bash
grep -n "findByCredentialId\|getStatus()\|CredentialStatus" server/src/main/java/com/crosscert/passkey/credential/service/AuthenticationService.java
```

`status != ACTIVE` 분기를 다음 패턴으로 교체:

```java
if (credential.getStatus() == CredentialStatus.SUSPENDED) {
  log.warn(
      "credential.assertion.rejected.suspended tenantId={} credentialDbId={}",
      credential.getTenantId(),
      credential.getId());
  meterRegistry
      .counter("credential.assertion.rejected", "reason", "suspended")
      .increment();
  throw new BusinessException(ErrorCode.CREDENTIAL_SUSPENDED);
}
if (credential.getStatus() == CredentialStatus.REVOKED) {
  throw new BusinessException(ErrorCode.CREDENTIAL_REVOKED);
}
```

> AuthenticationService에 이미 MeterRegistry 주입이 없다면, 메트릭 증가 라인은 생략 가능 (기존 ceremony metrics 패턴 확인 후 통일). 분기 자체는 필수.

- [ ] **Step 10.3: allowCredentials 호출자 필터링 점검**

`AuthenticationOptionsBuilder` 또는 options 생성 service를 찾고 (`grep -rn "allowCredentials\|AuthenticationOptions" server/src/main/java | head`), `findAllByTenantUserId` 호출 결과를 `c -> c.isActive()` 또는 `findAllActiveByTenantUserId`로 필터링하도록 수정. 이미 REVOKED를 거르고 있다면 SUSPENDED도 `c.getStatus() == ACTIVE`로 자연스럽게 거른 형태로 통일.

- [ ] **Step 10.4: 컴파일 + 기존 슬라이스/유닛 테스트 실행**

Run: `cd server && ./gradlew compileJava compileTestJava`

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.*"`

Expected: BUILD SUCCESSFUL. 기존 unit 테스트 그대로 통과.

- [ ] **Step 10.5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/service/AuthenticationService.java \
        server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java
git commit -m "feat(auth): reject assertion on SUSPENDED credential + filter allowCredentials

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: PO 수동 unsuspend — service + controller endpoint

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/service/CredentialLifecycleService.java`
- Modify: `server/src/main/java/com/crosscert/passkey/admin/controller/AdminCredentialController.java`

- [ ] **Step 11.1: 서비스 메서드 추가**

`CredentialLifecycleService.java`에 `revoke(UUID, CredentialRevokedReason)` 다음 위치에 추가:

```java
  /**
   * Platform Operator manual unsuspend. Restores ACTIVE; preserves suspendedAt/Reason for
   * forensics; sets unsuspendedAt/By. No refresh token re-issue — user must complete a fresh
   * assertion to receive a new session.
   */
  @Transactional
  public CredentialView unsuspend(UUID credentialId, String actorId) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    String previousReason = c.getSuspendedReason() == null ? "" : c.getSuspendedReason();
    c.unsuspend(actorId); // throws CREDENTIAL_INVALID_STATE on wrong state
    auditService.append(
        AuditEventType.CREDENTIAL_UNSUSPENDED,
        ActorType.ADMIN,
        actorId,
        "CREDENTIAL",
        c.getId().toString(),
        Map.of("previousReason", previousReason));
    log.info(
        "credential.unsuspend tenantId={} credentialDbId={} actor={}",
        c.getTenantId(),
        c.getId(),
        actorId);
    return CredentialView.from(c);
  }
```

> `ActorType.ADMIN`은 기존 enum에 존재함을 확인.

- [ ] **Step 11.2: 컨트롤러 endpoint 추가**

`AdminCredentialController.java` 안 (다른 endpoint들 사이에 자연스러운 위치):

```java
  @PostMapping("/{credentialId}/unsuspend")
  @ResponseStatus(HttpStatus.OK)
  @Operation(
      summary = "Unsuspend a credential (PLATFORM_OPERATOR only)",
      description =
          "Restores SUSPENDED → ACTIVE. Preserves suspendedAt/Reason for forensics."
              + " Refresh tokens are not auto-reissued — user must re-authenticate.")
  public ApiResponse<CredentialView> unsuspend(
      @PathVariable UUID tenantId, @PathVariable UUID credentialId) {
    AdminAuthz.requirePlatformOperator();
    AdminAuthz.requireTenantAccess(tenantId);
    return ApiResponse.ok(lifecycle.unsuspend(credentialId, AdminAuthz.currentActorId()));
  }
```

> **참고**: `AdminAuthz` API는 기존 admin controller들이 사용하는 패턴을 그대로 따른다. 정확한 helper 메서드명은 다른 admin controller(`AdminCredentialController` 내 다른 endpoint 또는 `AdminAttestationPolicyController`)에서 확인 후 사용. PLATFORM_OPERATOR 강제는 `@PreAuthorize("hasRole('PLATFORM_OPERATOR')")`로 교체 가능 — 기존 컨벤션 따른다.

- [ ] **Step 11.3: 컴파일 확인**

Run: `cd server && ./gradlew compileJava`

Expected: BUILD SUCCESSFUL.

- [ ] **Step 11.4: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/service/CredentialLifecycleService.java \
        server/src/main/java/com/crosscert/passkey/admin/controller/AdminCredentialController.java
git commit -m "feat(admin): POST /credentials/{id}/unsuspend for PLATFORM_OPERATOR

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Integration tests — end-to-end

이 task는 다섯 개 통합 테스트 클래스를 만든다. 각각 별도 sub-step.

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/integration/credential/MdsScanIntegrationTest.java`
- Test: `server/src/test/java/com/crosscert/passkey/integration/credential/MdsScanRetryIntegrationTest.java`
- Test: `server/src/test/java/com/crosscert/passkey/integration/credential/AssertionWithSuspendedCredentialIntegrationTest.java`
- Test: `server/src/test/java/com/crosscert/passkey/integration/credential/AuthenticationOptionsExcludesSuspendedTest.java`
- Test: `server/src/test/java/com/crosscert/passkey/integration/credential/AdminUnsuspendIntegrationTest.java`

- [ ] **Step 12.1: `MdsScanIntegrationTest` — 두 tenant cross-tenant scan**

`MdsScanIntegrationTest.java`:

```java
package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;

/**
 * End-to-end: publish MdsBlobRefreshedEvent with a fixture critical AAGUID → assert credentials
 * for that AAGUID transition to SUSPENDED, refresh tokens are revoked, audit row appears, metrics
 * increment.
 */
class MdsScanIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired private ApplicationEventPublisher events;
  @Autowired private MeterRegistry meterRegistry;

  @Test
  void scan_suspendsAffectedCredentials_acrossTenants() throws Exception {
    UUID tenant1 = createTenant("t1");
    UUID tenant2 = createTenant("t2");
    UUID userA = createUser(tenant1, "user-a");
    UUID userB = createUser(tenant2, "user-b");
    UUID criticalAaguid = UUID.randomUUID();
    UUID safeAaguid = UUID.randomUUID();
    UUID credA1 = createCredential(tenant1, userA, criticalAaguid, "ACTIVE");
    UUID credA2 = createCredential(tenant1, userA, safeAaguid, "ACTIVE");
    UUID credB = createCredential(tenant2, userB, criticalAaguid, "ACTIVE");
    insertLiveRefreshToken(tenant1, userA);

    MetadataBlob blob =
        new MetadataBlob(
            4711L,
            Instant.now().plusSeconds(86400),
            List.of(
                new MetadataEntry(criticalAaguid, List.of(), List.of(StatusReport.REVOKED)),
                new MetadataEntry(safeAaguid, List.of(), List.of(StatusReport.FIDO_CERTIFIED))));
    events.publishEvent(new MdsBlobRefreshedEvent(blob, Instant.now()));

    await()
        .atMost(Duration.ofSeconds(10))
        .untilAsserted(
            () -> {
              assertThat(statusOf(credA1)).isEqualTo(CredentialStatus.SUSPENDED.name());
              assertThat(statusOf(credB)).isEqualTo(CredentialStatus.SUSPENDED.name());
              assertThat(statusOf(credA2)).isEqualTo(CredentialStatus.ACTIVE.name());
              assertThat(refreshTokenLive(userA)).isFalse();
              assertThat(auditCount(tenant1, AuditEventType.CREDENTIAL_AUTO_SUSPENDED))
                  .isEqualTo(1);
              assertThat(auditCount(tenant2, AuditEventType.CREDENTIAL_AUTO_SUSPENDED))
                  .isEqualTo(1);
              assertThat(meterRegistry.counter("mds.scan.suspended.total").count())
                  .isGreaterThanOrEqualTo(2);
            });
  }
}
```

> `AdminEnabledIntegrationTestBase`가 helper로 `createTenant/createUser/createCredential/insertLiveRefreshToken/statusOf/refreshTokenLive/auditCount`를 제공하는 패턴을 가정. 실제 base 클래스에 없는 helper는 본 테스트의 inner private method로 추가하거나 base에 합류. (기존 `AdminEnabledIntegrationTestBase` 확인 후 결정 — 가장 가벼운 추가만.)

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.credential.MdsScanIntegrationTest"`

Expected: 1/1 passing.

- [ ] **Step 12.2: `MdsScanRetryIntegrationTest` — F5 lingering token cleanup**

`MdsScanRetryIntegrationTest.java`:

```java
package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Simulates a previous scan that SUSPENDED a credential but failed to revoke the refresh token
 * (F5 boost path). A subsequent scan — even with no new critical AAGUIDs in the BLOB — must clean
 * up the lingering live token.
 */
class MdsScanRetryIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired private ApplicationEventPublisher events;

  @Test
  void scan_cleansUpLingeringTokens_evenWithNoNewCriticalAaguids() {
    UUID tenant = createTenant("t");
    UUID user = createUser(tenant, "u");
    UUID aaguid = UUID.randomUUID();
    // Pre-state: SUSPENDED credential + live token (F5 leftover).
    UUID cred = createCredential(tenant, user, aaguid, "SUSPENDED");
    setSuspendedMetadata(cred, "MDS_REVOKED:REVOKED");
    insertLiveRefreshToken(tenant, user);
    // Empty BLOB (no critical AAGUIDs).
    MetadataBlob empty = new MetadataBlob(5000L, Instant.now().plusSeconds(86400), List.of());
    events.publishEvent(new MdsBlobRefreshedEvent(empty, Instant.now()));
    // Token should be revoked even though BLOB carries no critical AAGUID, via the lingering
    // SUSPENDED+live-token query.
    await()
        .atMost(Duration.ofSeconds(10))
        .untilAsserted(() -> assertThat(refreshTokenLive(user)).isFalse());
  }
}
```

> **참고**: scan 본문이 `criticalAaguids.isEmpty()` early return이라면 lingering cleanup이 동작하지 않을 수 있다. 그 경우 service에서 lingering 쿼리를 early return 앞으로 옮기거나, "조건: SUSPENDED credential이 하나라도 있으면 lingering 청소" 분기를 추가한다. 본 plan에서는 후자(early return 제거)로 가정 — `criticalAaguids.isEmpty()` 시에도 lingering token 청소만 수행하고 종료. Task 8.3 코드를 다음과 같이 조정:
>
> ```java
> if (criticalAaguids.isEmpty()) {
>   // still clean up lingering tokens from a prior F5
>   Set<UUID> lingering = credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken();
>   if (!lingering.isEmpty()) {
>     int revoked = refreshTokenAdminWriter.revokeAllByTenantUserIds(lingering, RevokedReason.CREDENTIAL_SUSPENDED);
>     log.info("mds.scan.tokens.lingering.revoked count={} users={}", revoked, lingering.size());
>   }
>   return ScanResult.empty(blob.serialNumber());
> }
> ```
>
> 이 조정은 Task 8.3 작업 시 함께 반영. Task 8의 Mockito 테스트 중 `scan_noCriticalEntries_skipsAllWrites`도 그에 맞춰 약간 수정 필요: `verify(refreshTokenAdminWriter, never()...)` → `when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken()).thenReturn(Set.of())` + 동일 결과.

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.credential.MdsScanRetryIntegrationTest"`

Expected: 1/1 passing.

- [ ] **Step 12.3: `AssertionWithSuspendedCredentialIntegrationTest`**

`AssertionWithSuspendedCredentialIntegrationTest.java`:

```java
package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * If an RP submits an assertion for a SUSPENDED credential (out-of-band — past the
 * allowCredentials filter), the server must respond 403 P016 CREDENTIAL_SUSPENDED.
 */
class AssertionWithSuspendedCredentialIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Test
  void assertion_onSuspendedCredential_yields403_P016() throws Exception {
    UUID tenant = createTenant("t");
    UUID user = createUser(tenant, "u");
    UUID cred = createCredential(tenant, user, UUID.randomUUID(), "SUSPENDED");
    setSuspendedMetadata(cred, "MDS_REVOKED:REVOKED");
    String credentialIdBase64Url = credentialIdOf(cred);

    // Simulate an assertion verify call addressing this credential.
    mockMvc.perform(
            post("/api/v1/rp/auth/verify")
                .header("X-API-Key", apiKeyOf(tenant))
                .contentType("application/json")
                .content(fakeAssertionVerifyJson(credentialIdBase64Url)))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error.code").value("P016"));
  }
}
```

> `fakeAssertionVerifyJson`는 base 클래스 헬퍼이거나, 본 테스트 안 정적 메서드로 둔 fixture(메모리에서 만든 challenge + 시그니처 placeholder). 인증 단계에서 `findByCredentialId` 직후 status 검사가 throw하는지 검증이므로, **assertion 본문이 완전히 유효하지 않아도 SUSPENDED 검사가 먼저 트리거되도록** AuthenticationService의 분기 위치 확인. status 검사가 시그니처 검증 이전에 있는 게 의도.

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.credential.AssertionWithSuspendedCredentialIntegrationTest"`

Expected: 1/1 passing.

- [ ] **Step 12.4: `AuthenticationOptionsExcludesSuspendedTest`**

`AuthenticationOptionsExcludesSuspendedTest.java`:

```java
package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

class AuthenticationOptionsExcludesSuspendedTest extends AdminEnabledIntegrationTestBase {

  @Test
  void options_returnsOnlyActiveCredentials() throws Exception {
    UUID tenant = createTenant("t");
    UUID user = createUser(tenant, "u");
    UUID cActive = createCredential(tenant, user, UUID.randomUUID(), "ACTIVE");
    UUID cSusp = createCredential(tenant, user, UUID.randomUUID(), "SUSPENDED");
    UUID cRev = createCredential(tenant, user, UUID.randomUUID(), "REVOKED");

    MvcResult res =
        mockMvc.perform(
                post("/api/v1/rp/auth/options")
                    .header("X-API-Key", apiKeyOf(tenant))
                    .contentType("application/json")
                    .content("{\"externalUserId\":\"" + externalIdOf(user) + "\"}"))
            .andReturn();

    String body = res.getResponse().getContentAsString();
    assertThat(body).contains(credentialIdOf(cActive));
    assertThat(body).doesNotContain(credentialIdOf(cSusp));
    assertThat(body).doesNotContain(credentialIdOf(cRev));
  }
}
```

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.credential.AuthenticationOptionsExcludesSuspendedTest"`

Expected: 1/1 passing.

- [ ] **Step 12.5: `AdminUnsuspendIntegrationTest`**

`AdminUnsuspendIntegrationTest.java`:

```java
package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AdminUnsuspendIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Test
  void unsuspend_byPlatformOperator_restoresActive_andAudits() throws Exception {
    UUID tenant = createTenant("t");
    UUID user = createUser(tenant, "u");
    UUID cred = createCredential(tenant, user, UUID.randomUUID(), "SUSPENDED");
    setSuspendedMetadata(cred, "MDS_REVOKED:REVOKED");

    mockMvc.perform(
            post("/api/v1/admin/tenants/" + tenant + "/credentials/" + cred + "/unsuspend")
                .with(platformOperatorSession()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.status").value("ACTIVE"));

    assertThat(statusOf(cred)).isEqualTo(CredentialStatus.ACTIVE.name());
    assertThat(suspendedReasonOf(cred)).isEqualTo("MDS_REVOKED:REVOKED"); // preserved
    assertThat(unsuspendedByOf(cred)).isNotNull();
    assertThat(auditCount(tenant, AuditEventType.CREDENTIAL_UNSUSPENDED)).isEqualTo(1);
  }

  @Test
  void unsuspend_byRpAdmin_isForbidden() throws Exception {
    UUID tenant = createTenant("t");
    UUID user = createUser(tenant, "u");
    UUID cred = createCredential(tenant, user, UUID.randomUUID(), "SUSPENDED");
    mockMvc.perform(
            post("/api/v1/admin/tenants/" + tenant + "/credentials/" + cred + "/unsuspend")
                .with(rpAdminSession(tenant)))
        .andExpect(status().isForbidden());
  }

  @Test
  void unsuspend_onActiveCredential_yields409_P017() throws Exception {
    UUID tenant = createTenant("t");
    UUID user = createUser(tenant, "u");
    UUID cred = createCredential(tenant, user, UUID.randomUUID(), "ACTIVE");
    mockMvc.perform(
            post("/api/v1/admin/tenants/" + tenant + "/credentials/" + cred + "/unsuspend")
                .with(platformOperatorSession()))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.error.code").value("P017"));
  }
}
```

> 세션/principal helper(`platformOperatorSession`, `rpAdminSession`)는 기존 admin integration test에서 패턴 차용. 정확한 helper명은 `AdminApiKeyController` 같은 기존 admin 테스트를 참조.

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.credential.AdminUnsuspendIntegrationTest"`

Expected: 3/3 passing.

- [ ] **Step 12.6: Integration 테스트 일괄 실행 + 커밋**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.credential.*"`

Expected: 모든 integration 테스트 통과.

```bash
git add server/src/test/java/com/crosscert/passkey/integration/credential/MdsScanIntegrationTest.java \
        server/src/test/java/com/crosscert/passkey/integration/credential/MdsScanRetryIntegrationTest.java \
        server/src/test/java/com/crosscert/passkey/integration/credential/AssertionWithSuspendedCredentialIntegrationTest.java \
        server/src/test/java/com/crosscert/passkey/integration/credential/AuthenticationOptionsExcludesSuspendedTest.java \
        server/src/test/java/com/crosscert/passkey/integration/credential/AdminUnsuspendIntegrationTest.java
git commit -m "test(mds): end-to-end integration coverage for MDS post-revocation pipeline

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

만약 helper들이 base 클래스에 부재해 추가 작성이 필요했다면 그 변경도 함께 commit:

```bash
git add server/src/test/java/com/crosscert/passkey/integration/support/AdminEnabledIntegrationTestBase.java
git commit --amend --no-edit
```

---

## Task 13: ArchUnit 규칙 + 최종 `./gradlew check`

**Files:**
- Modify: `server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java`

- [ ] **Step 13.1: ArchUnit 규칙 추가**

`PackageArchitectureTest.java`에 새 규칙 추가:

```java
  @ArchTest
  static final ArchRule mds_metadata_package_does_not_depend_on_admin =
      noClasses()
          .that()
          .resideInAPackage("..credential.metadata..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("..admin..")
          .because(
              "MDS revocation scan must run independently of admin console (cron path);"
                  + " a dependency on admin would force the cron job to load admin config.");
```

> 기존 ArchUnit 패턴 (Rule 1~8 등) 따라 자연스러운 위치에 삽입.

- [ ] **Step 13.2: ArchUnit 테스트 실행**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.architecture.PackageArchitectureTest"`

Expected: 모든 규칙 통과.

- [ ] **Step 13.3: 전체 `./gradlew check`**

Run: `cd server && ./gradlew check`

Expected: BUILD SUCCESSFUL (slice + integration + ArchUnit + spotless). 실패 시 → 메시지에 따라 fix (테스트가 base helper에 의존하면 helper 추가, spotless 위반이면 `./gradlew spotlessApply` 후 재실행).

- [ ] **Step 13.4: 커밋**

```bash
git add server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java
git commit -m "test(arch): metadata package must not depend on admin package

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 13.5: 변경 요약 확인**

Run:
```bash
git log --oneline main..HEAD
git diff main..HEAD --stat | tail -5
```

Expected: ~13 커밋, 신규 파일 17개·수정 파일 12개 내외.

---

## Self-Review

### 1. Spec coverage

| Spec 항목 | 구현 Task |
|---|---|
| §5.1 Flyway V<n>__credential_suspended_status.sql | Task 1 |
| §5.2 enum 확장 (CredentialStatus, CredentialSuspendedReason) | Tasks 2, 3 |
| §5.3 도메인 메서드 suspend/unsuspend | Task 2 |
| §5.4 ErrorCode CREDENTIAL_SUSPENDED/INVALID_STATE | Task 4 |
| §5.5 AuditEventType CREDENTIAL_AUTO_SUSPENDED/UNSUSPENDED | Task 4 |
| §6.2(a) MdsBlobRefreshedEvent record | Task 9 |
| §6.2(b) MdsBlobProvider publishEvent | Task 9 |
| §6.2(c) MdsRevocationScanListener @Async | Task 9 |
| §6.2(d) MdsRevocationScanService | Task 8 |
| §6.2(e) CredentialAdminWriter SELECT FOR UPDATE + batch | Task 6 |
| §6.2(f) RefreshTokenAdminWriter | Task 7 |
| §6.2(g) CredentialLifecycleService.unsuspend | Task 11 |
| §6.2(h) AdminCredentialController endpoint | Task 11 |
| §6.2(i) AuthenticationService 분기 + allowCredentials 필터 | Task 10 |
| §7.4 트랜잭션 분리 (admin 1: credential, admin 2: tokens) | Task 6/7 분리 + Task 8 호출 순서 |
| §5.2 보강 (lingering token cleanup) | Task 6 + Task 8 (early-return 분기 보정) |
| §8 메트릭 (mds.scan.*) | Task 8 |
| §9 테스트 피라미드 (unit + slice + integration) | Tasks 2/6/7/8/9 + Task 12 |
| §9.4 ArchUnit 추가 | Task 13 |
| §5 CredentialView 필드 노출 | Task 5 |
| §3 RevokedReason.CREDENTIAL_SUSPENDED | Task 4 |

스펙 §11(미해결) 항목들은 구현 단계 노트로 작성됨 (FOR UPDATE timeout, manual trigger endpoint 위치 등). manual trigger endpoint(`POST /api/v1/admin/mds/scan` 또는 `/_diag/mds-scan`)는 본 plan 범위에서 제외 — 이벤트 publishEvent로 동일 효과를 얻을 수 있고, MVP 이후 별도 task로.

### 2. Placeholder scan

- "TBD" / "TODO" / "fill in" 없음 ✓
- 모든 step에 실제 코드 또는 명령 ✓
- "Similar to Task N" 패턴 없음 — 각 step에 코드 repeat ✓
- Task 6의 ORA 호환성 fallback은 명시적인 분기 가이드 (placeholder가 아님) ✓
- Task 10의 AuthenticationOptionsBuilder 위치는 구현자가 grep으로 찾도록 안내 — 단일 명확한 패치 가이드 포함 ✓

### 3. Type consistency

| 심볼 | 일관 사용 위치 |
|---|---|
| `CredentialAdminWriter.SuspendedRow(UUID id, UUID tenantId, UUID tenantUserId, UUID aaguid)` | Task 6 정의 → Task 8 unit test (`new SuspendedRow(...)`)에서 동일 시그니처 사용 ✓ |
| `ScanResult(long blobSerial, int credentialsAffected, int tokensRevoked, Set<UUID> tenantsAffected)` | Task 8 정의 → Task 8 unit test에서 동일 ✓ |
| `MetadataBlob(long, Instant, List<MetadataEntry>)` | Task 8/9/12 일관. 실제 record 정의와 다르면 모든 사용처를 fixture builder 패턴으로 교체 (가드 노트 포함) ✓ |
| `MdsBlobRefreshedEvent(MetadataBlob blob, Instant refreshedAt)` | Task 9 정의 → Task 9/12 일관 ✓ |
| `RevokedReason.CREDENTIAL_SUSPENDED` | Task 4 정의 → Tasks 7, 8, 10 일관 ✓ |
| `AuditEventType.CREDENTIAL_AUTO_SUSPENDED`, `CREDENTIAL_UNSUSPENDED` | Task 4 정의 → Tasks 8, 11 일관 ✓ |
| `ErrorCode.CREDENTIAL_SUSPENDED` (P016) / `CREDENTIAL_INVALID_STATE` (P017) | Task 4 정의 → Tasks 2, 10, 11, 12 일관 ✓ |
| `Credential.suspend(String reasonDetail)` / `unsuspend(String actorId)` | Task 2 정의 → Task 11, Task 2 테스트 일관 ✓ |

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-23-mds-post-registration-revocation.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — 각 task당 fresh subagent dispatch + two-stage review. 13개 task로 분해돼 있어 적합.

**2. Inline Execution** — 현재 세션에서 순차 실행 + 체크포인트별 사용자 확인.

**어느 방식으로 진행할까요?**
