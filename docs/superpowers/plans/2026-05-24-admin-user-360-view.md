# Admin 사용자 360° 뷰 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** RP 고객사 운영자가 admin 콘솔의 사용자 상세 화면에서 (1) AAGUID 라벨로 인증기를 식별하고, (2) 사용자의 활성 refresh token을 보고 개별/전체 revoke하고, (3) credentials를 페이지네이션 + 행 액션으로 관리할 수 있게 한다.

**Architecture:** Brownfield 작업 — 기존 `AdminEndUserController` / `UserDetailPage` 확장 + `AaguidLabelResolver` 신규 service + paged credentials/refresh-tokens endpoint 2개 + 개별 token revoke endpoint 1개 + 클라이언트 탭 UI 재구성. DB 스키마 변경 없음. `EndUserDetailView` 응답 변경(Breaking, admin console만 소비)은 server/client 동시 커밋.

**Tech Stack:** Server — Spring Boot 3.5, Java 17, JPA, Oracle 19c VPD. Client — Vite + React 18 + TS + Tailwind + shadcn/ui + TanStack Query + React Router v6 + date-fns. Tests — JUnit 5 + Spring slice/integration, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-05-24-admin-user-360-view-design.md` (브렌치 동일 디렉터리).

---

## 파일 구조 (영향 받는 파일)

### 서버 (`server/`)
- **수정**: `src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java` — `EndUserDetailView` 변경 + paged endpoints 2개 추가
- **신규**: `src/main/java/com/crosscert/passkey/admin/controller/AdminRefreshTokenController.java` — DELETE single token
- **신규**: `src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabelResolver.java` — MDS lookup + cache
- **수정**: `src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java` — `REFRESH_TOKEN_REVOKED` 추가
- **수정**: `src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java` — paged + count 메서드
- **수정**: `src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenRepository.java` — paged active/all + count
- **신규 테스트**: `src/test/java/com/crosscert/passkey/unit/credential/metadata/AaguidLabelResolverTest.java`
- **신규 테스트**: `src/test/java/com/crosscert/passkey/slice/admin/AdminEndUserControllerPagedSliceTest.java`
- **신규 테스트**: `src/test/java/com/crosscert/passkey/slice/admin/AdminRefreshTokenControllerSliceTest.java`
- **신규 테스트**: `src/test/java/com/crosscert/passkey/integration/admin/AdminUserViewIntegrationTest.java`

### 클라이언트 (`admin/`)
- **수정**: `src/types/api.ts` — `EndUserDetailView` 변경, 신규 타입 (`UserCredentialItemView`, `RefreshTokenView`, `AaguidLabel`) 추가
- **신규**: `src/components/AaguidLabel.tsx` — MDS 라벨 + 미등록 배지
- **신규**: `src/components/ConfirmDialog.tsx` — Dialog 기반 confirm 모달 (AlertDialog 의존성 회피)
- **수정**: `src/pages/tenant/UserDetailPage.tsx` — 탭 구조 재구성
- **신규**: `src/pages/tenant/user-detail/CredentialsTabPanel.tsx` — Credentials 탭 컨텐츠
- **신규**: `src/pages/tenant/user-detail/SessionsTabPanel.tsx` — Sessions 탭 컨텐츠
- **신규 테스트**: `src/components/AaguidLabel.test.tsx`
- **신규 테스트**: `tests/admin/user-detail.spec.ts` — Playwright E2E

---

## Phase 1: 서버 (1주차)

### Task 1: `REFRESH_TOKEN_REVOKED` audit event type 추가

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java`

- [ ] **Step 1: 기존 enum 확인 (placeholder 없이 정확한 위치 파악)**

Run: `grep -n "USER_FORCE_LOGOUT\|// ---------- ADMIN ----------" server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java`

Expected: `USER_FORCE_LOGOUT` 라인 번호 출력. `// ---------- ADMIN ----------` 섹션도 함께.

- [ ] **Step 2: enum 값 추가**

`USER_FORCE_LOGOUT,` 바로 다음 줄에 추가:

```java
  /** Admin revoked a single refresh token by id (per-session control). Sibling of USER_FORCE_LOGOUT
   *  which mass-revokes; this is the targeted "kill one device" lever. */
  REFRESH_TOKEN_REVOKED,
```

- [ ] **Step 3: 컴파일 통과 확인**

Run: `cd server && ./gradlew compileJava --console=plain`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/audit/domain/AuditEventType.java
git commit -m "feat(audit): add REFRESH_TOKEN_REVOKED event type"
```

---

### Task 2: `AaguidLabelResolver` 신규 service — failing test

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/unit/credential/metadata/AaguidLabelResolverTest.java`
- Create (Task 3에서): `server/src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabelResolver.java`
- Create (Task 3에서): `server/src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabel.java`

- [ ] **Step 1: failing test 작성**

```java
package com.crosscert.passkey.unit.credential.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.credential.metadata.AaguidLabel;
import com.crosscert.passkey.credential.metadata.AaguidLabelResolver;
import com.crosscert.passkey.credential.metadata.MdsBlobProvider;
import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.MetadataStatement;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AaguidLabelResolverTest {

  @Test
  void resolve_null_returnsUnknown() {
    AaguidLabelResolver resolver = newResolverWithBlob(null);
    AaguidLabel label = resolver.resolve(null);
    assertThat(label.aaguid()).isNull();
    assertThat(label.displayName()).isEqualTo("unknown");
    assertThat(label.fromMds()).isFalse();
  }

  @Test
  void resolve_blobMissing_returnsUuidStringAndFromMdsFalse() {
    UUID aaguid = UUID.randomUUID();
    AaguidLabelResolver resolver = newResolverWithBlob(null);
    AaguidLabel label = resolver.resolve(aaguid);
    assertThat(label.aaguid()).isEqualTo(aaguid);
    assertThat(label.displayName()).isEqualTo(aaguid.toString());
    assertThat(label.fromMds()).isFalse();
  }

  @Test
  void resolve_blobMiss_returnsUuidStringAndFromMdsFalse() {
    UUID present = UUID.randomUUID();
    UUID missing = UUID.randomUUID();
    AaguidLabelResolver resolver = newResolverWithEntries(List.of(entry(present, "YubiKey 5")));
    AaguidLabel label = resolver.resolve(missing);
    assertThat(label.displayName()).isEqualTo(missing.toString());
    assertThat(label.fromMds()).isFalse();
  }

  @Test
  void resolve_blobHit_returnsDescriptionAndFromMdsTrue() {
    UUID aaguid = UUID.randomUUID();
    AaguidLabelResolver resolver = newResolverWithEntries(List.of(entry(aaguid, "YubiKey 5C NFC")));
    AaguidLabel label = resolver.resolve(aaguid);
    assertThat(label.displayName()).isEqualTo("YubiKey 5C NFC");
    assertThat(label.fromMds()).isTrue();
  }

  @Test
  void onBlobRefresh_rebuildsCache() {
    UUID a = UUID.randomUUID();
    UUID b = UUID.randomUUID();
    MdsBlobProvider provider = mock(MdsBlobProvider.class);
    AtomicReference<MetadataBlob> ref = new AtomicReference<>(blobOf(List.of(entry(a, "A"))));
    when(provider.getLastBlob()).thenReturn(ref);
    AaguidLabelResolver resolver = new AaguidLabelResolver(provider);
    // warm the cache to the first blob
    assertThat(resolver.resolve(a).displayName()).isEqualTo("A");
    assertThat(resolver.resolve(b).fromMds()).isFalse();
    // simulate blob rotation
    ref.set(blobOf(List.of(entry(b, "B"))));
    resolver.onBlobRefresh(new MdsBlobRefreshedEvent(ref.get(), Instant.now()));
    assertThat(resolver.resolve(b).displayName()).isEqualTo("B");
    assertThat(resolver.resolve(a).fromMds()).isFalse();
  }

  // ---- helpers ------------------------------------------------------------

  private static AaguidLabelResolver newResolverWithBlob(MetadataBlob blob) {
    MdsBlobProvider provider = mock(MdsBlobProvider.class);
    when(provider.getLastBlob()).thenReturn(new AtomicReference<>(blob));
    return new AaguidLabelResolver(provider);
  }

  private static AaguidLabelResolver newResolverWithEntries(List<MetadataEntry> entries) {
    return newResolverWithBlob(blobOf(entries));
  }

  private static MetadataEntry entry(UUID aaguid, String description) {
    MetadataEntry e = mock(MetadataEntry.class);
    when(e.aaguid()).thenReturn(aaguid);
    MetadataStatement stmt = mock(MetadataStatement.class);
    when(stmt.description()).thenReturn(description);
    when(e.metadataStatement()).thenReturn(stmt);
    return e;
  }

  private static MetadataBlob blobOf(List<MetadataEntry> entries) {
    MetadataBlob blob = mock(MetadataBlob.class);
    when(blob.entries()).thenReturn(entries);
    return blob;
  }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.metadata.AaguidLabelResolverTest" --console=plain`
Expected: COMPILE FAILURE — `AaguidLabel`, `AaguidLabelResolver` 클래스가 존재하지 않음.

---

### Task 3: `AaguidLabel` record + `AaguidLabelResolver` 구현

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabel.java`
- Create: `server/src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabelResolver.java`

- [ ] **Step 1: `AaguidLabel` record 작성**

```java
package com.crosscert.passkey.credential.metadata;

import java.util.UUID;

/**
 * Result of {@link AaguidLabelResolver#resolve}. {@code fromMds=true} means the {@code displayName}
 * is the MDS metadataStatement description for a known authenticator; {@code false} means the MDS
 * BLOB had no entry for this AAGUID (platform authenticators like iCloud Keychain are common
 * MDS-misses) and {@code displayName} is the raw UUID string for display.
 */
public record AaguidLabel(UUID aaguid, String displayName, boolean fromMds) {}
```

- [ ] **Step 2: `AaguidLabelResolver` 구현**

```java
package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * Resolves an AAGUID to a human-readable label by looking it up in the currently-cached MDS BLOB.
 * Falls back to the raw UUID string when (a) the BLOB hasn't loaded yet, or (b) the AAGUID isn't
 * registered in MDS (common for platform authenticators — iCloud Keychain, Windows Hello, Google
 * Password Manager are not in the FIDO MDS).
 *
 * <p>Caches the AAGUID→entry map to avoid an O(N) scan of {@code blob.entries()} per call. Cache
 * is rebuilt on {@link MdsBlobRefreshedEvent} — which fires from {@link MdsBlobProvider#refresh()}
 * and is guaranteed to land after listener registration (warm-up runs on
 * {@code ApplicationReadyEvent}).
 */
@Slf4j
@Service
public class AaguidLabelResolver {

  private final MdsBlobProvider provider;
  private volatile Map<UUID, MetadataEntry> cache;
  private volatile MetadataBlob cachedFor;

  public AaguidLabelResolver(MdsBlobProvider provider) {
    this.provider = provider;
  }

  public AaguidLabel resolve(UUID aaguid) {
    if (aaguid == null) {
      return new AaguidLabel(null, "unknown", false);
    }
    MetadataEntry entry = lookup(aaguid);
    if (entry == null || entry.metadataStatement() == null
        || entry.metadataStatement().description() == null) {
      return new AaguidLabel(aaguid, aaguid.toString(), false);
    }
    return new AaguidLabel(aaguid, entry.metadataStatement().description(), true);
  }

  @EventListener(MdsBlobRefreshedEvent.class)
  void onBlobRefresh(MdsBlobRefreshedEvent event) {
    // Drop the cache; next resolve() rebuilds from the new blob via lookup().
    this.cache = null;
    this.cachedFor = null;
    log.info("aaguid.cache.invalidated reason=blobRefresh");
  }

  private MetadataEntry lookup(UUID aaguid) {
    MetadataBlob current = provider.getLastBlob().get();
    if (current == null) {
      return null;
    }
    Map<UUID, MetadataEntry> snapshot = this.cache;
    if (snapshot == null || this.cachedFor != current) {
      snapshot = build(current.entries());
      this.cache = snapshot;
      this.cachedFor = current;
    }
    return snapshot.get(aaguid);
  }

  private static Map<UUID, MetadataEntry> build(List<MetadataEntry> entries) {
    Map<UUID, MetadataEntry> map = new HashMap<>(entries.size() * 2);
    for (MetadataEntry e : entries) {
      if (e != null && e.aaguid() != null) {
        map.put(e.aaguid(), e);
      }
    }
    return map;
  }
}
```

- [ ] **Step 3: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.metadata.AaguidLabelResolverTest" --console=plain`
Expected: BUILD SUCCESSFUL, 5 tests passed

- [ ] **Step 4: spotless 적용 + 커밋**

```bash
cd server && ./gradlew spotlessApply --console=plain
cd ..
git add server/src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabel.java \
        server/src/main/java/com/crosscert/passkey/credential/metadata/AaguidLabelResolver.java \
        server/src/test/java/com/crosscert/passkey/unit/credential/metadata/AaguidLabelResolverTest.java
git commit -m "feat(mds): AaguidLabelResolver — MDS-backed AAGUID label lookup with blob-rotation cache invalidation"
```

---

### Task 4: `CredentialRepository`에 paged 메서드 추가 — failing test

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/slice/credential/CredentialRepositoryPagedSliceTest.java` (신규)
- Modify (Task 5에서): `server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java`

- [ ] **Step 1: failing slice test 작성**

```java
package com.crosscert.passkey.slice.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.CredentialSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

class CredentialRepositoryPagedSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired CredentialRepository repo;
  @Autowired TenantSeed seed;
  @Autowired CredentialSeed credentialSeed;

  @Test
  void pagedByUser_returnsOnlyTargetUserRows_sortedByCreatedAtDesc() {
    UUID tenant = seed.createTenant("cred-page-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenant, "ua-" + UUID.randomUUID());
    UUID userB = seed.createUser(tenant, "ub-" + UUID.randomUUID());
    UUID c1 = credentialSeed.create(tenant, userA, CredentialStatus.ACTIVE);
    UUID c2 = credentialSeed.create(tenant, userA, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, userB, CredentialStatus.ACTIVE);

    Page<?> page =
        repo.findAllByTenantUserId(userA, PageRequest.of(0, 10));

    assertThat(page.getTotalElements()).isEqualTo(2);
    assertThat(page.getContent())
        .extracting(c -> ((com.crosscert.passkey.credential.domain.Credential) c).getId())
        .containsExactlyInAnyOrder(c1, c2);
  }

  @Test
  void countByUserAndStatus_perStatus() {
    UUID tenant = seed.createTenant("cred-count-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.SUSPENDED);
    credentialSeed.create(tenant, user, CredentialStatus.REVOKED);

    assertThat(repo.countByTenantUserIdAndStatus(user, CredentialStatus.ACTIVE)).isEqualTo(2L);
    assertThat(repo.countByTenantUserIdAndStatus(user, CredentialStatus.SUSPENDED)).isEqualTo(1L);
    assertThat(repo.countByTenantUserIdAndStatus(user, CredentialStatus.REVOKED)).isEqualTo(1L);
  }
}
```

- [ ] **Step 2: `CredentialSeed` 헬퍼가 없으면 발견하고 reuse — 확인**

Run: `find server/src/test -name "CredentialSeed*" -o -name "*Seed*.java" 2>/dev/null`
Expected: `TenantSeed.java`가 보임. `CredentialSeed`가 없으면 추가 필요. 있으면 시그니처 확인:
Run: `grep -n "public UUID create" server/src/test/java/com/crosscert/passkey/integration/support/CredentialSeed.java 2>/dev/null || echo "NOT FOUND — create CredentialSeed in next step"`

- [ ] **Step 3: `CredentialSeed`가 없으면 만든다 (있으면 스킵)**

만약 없으면, `TenantSeed.java`와 같은 디렉터리에:

```java
package com.crosscert.passkey.integration.support;

import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Minimal credential seeder for slice/integration tests. */
@Component
public class CredentialSeed {

  private final CredentialRepository repo;

  public CredentialSeed(CredentialRepository repo) {
    this.repo = repo;
  }

  @Transactional
  public UUID create(UUID tenantId, UUID tenantUserId, CredentialStatus status) {
    try {
      TenantContextHolder.set(new TenantContext(tenantId, "seed:" + tenantId));
      // NOTE: confirm Credential.create signature in production code before using.
      // If the production factory differs (e.g., requires public key bytes), adapt here.
      Credential c = Credential.createForTest(tenantId, tenantUserId, status);
      return repo.save(c).getId();
    } finally {
      TenantContextHolder.clear();
    }
  }
}
```

⚠️ `Credential.createForTest`가 없으면 production `Credential.create(...)` 시그니처 확인:
Run: `grep -n "public static Credential\|public Credential" server/src/main/java/com/crosscert/passkey/credential/domain/Credential.java | head -5`

production 메서드를 그대로 사용 (test helper 만들지 않음). seed 코드를 그에 맞춰 다시 작성. credential bytes 등 필수 인자는 dummy 값 사용. 이게 끝나면 spotless 적용.

- [ ] **Step 4: 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.credential.CredentialRepositoryPagedSliceTest" --console=plain 2>&1 | tail -15`
Expected: COMPILE FAILURE — `findAllByTenantUserId(UUID, Pageable)`, `countByTenantUserIdAndStatus` 메서드 없음.

---

### Task 5: `CredentialRepository`에 paged + count 메서드 구현

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java`

- [ ] **Step 1: repository에 메서드 추가**

`CredentialRepository.java`의 적당한 위치(기존 `findAllByTenantUserId` 옆)에 추가:

```java
  /** Paged variant of {@link #findAllByTenantUserId(UUID)} for admin user-detail views. */
  Page<Credential> findAllByTenantUserId(UUID tenantUserId, Pageable pageable);

  /** Count credentials of a single user with a given status. Used for admin user-detail summary. */
  long countByTenantUserIdAndStatus(UUID tenantUserId, CredentialStatus status);
```

import 추가:

```java
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
```

- [ ] **Step 2: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.credential.CredentialRepositoryPagedSliceTest" --console=plain`
Expected: BUILD SUCCESSFUL, 2 tests passed

- [ ] **Step 3: spotless + 커밋**

```bash
cd server && ./gradlew spotlessApply --console=plain
cd ..
git add server/src/main/java/com/crosscert/passkey/credential/repository/CredentialRepository.java \
        server/src/test/java/com/crosscert/passkey/slice/credential/CredentialRepositoryPagedSliceTest.java \
        server/src/test/java/com/crosscert/passkey/integration/support/CredentialSeed.java
git commit -m "feat(credential): paged findAllByTenantUserId + countByTenantUserIdAndStatus for admin user view"
```

---

### Task 6: `RefreshTokenRepository`에 paged active/all + count + 단건 조회 메서드 — failing test

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/slice/auth/RefreshTokenRepositoryPagedSliceTest.java` (신규)
- Modify (Task 7에서): `server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenRepository.java`

- [ ] **Step 1: failing slice test 작성**

```java
package com.crosscert.passkey.slice.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;

class RefreshTokenRepositoryPagedSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired RefreshTokenRepository repo;
  @Autowired TenantSeed seed;
  @Autowired RefreshTokenSeed tokenSeed;

  @Test
  void findActive_excludesExpiredAndRevoked() {
    UUID tenant = seed.createTenant("rt-active-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

    UUID activeId = tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertExpired(tenant, user, now.minusDays(1));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));

    assertThat(repo.findActiveByTenantUserId(user, now, PageRequest.of(0, 10))
            .getTotalElements())
        .isEqualTo(1L);
    assertThat(repo.countActiveByTenantUserId(user, now)).isEqualTo(1L);

    assertThat(
            repo.findActiveByTenantUserId(user, now, PageRequest.of(0, 10))
                .getContent()
                .get(0)
                .getId())
        .isEqualTo(activeId);
  }

  @Test
  void findAll_includesExpiredAndRevoked() {
    UUID tenant = seed.createTenant("rt-all-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

    tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertExpired(tenant, user, now.minusDays(1));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));

    assertThat(repo.findAllByTenantUserId(user, PageRequest.of(0, 10)).getTotalElements())
        .isEqualTo(3L);
  }
}
```

- [ ] **Step 2: `RefreshTokenSeed` 헬퍼 존재 확인**

Run: `ls server/src/test/java/com/crosscert/passkey/integration/support/RefreshTokenSeed.java 2>/dev/null || echo "NOT FOUND — create in next step"`

- [ ] **Step 3: `RefreshTokenSeed` 없으면 생성 (있으면 스킵 + 필요 메서드만 추가)**

`server/src/test/java/com/crosscert/passkey/integration/support/RefreshTokenSeed.java`:

```java
package com.crosscert.passkey.integration.support;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

/** Refresh-token seeder for admin-side slice/integration tests. Uses the admin (VPD-exempt) DS. */
@Component
public class RefreshTokenSeed {

  private final NamedParameterJdbcTemplate admin;

  public RefreshTokenSeed(@Qualifier("adminJdbcTemplate") NamedParameterJdbcTemplate admin) {
    this.admin = admin;
  }

  public UUID insertLive(UUID tenantId, UUID userId, OffsetDateTime expiresAt) {
    UUID id = UUID.randomUUID();
    OffsetDateTime now = OffsetDateTime.now();
    admin.update(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :exp, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("exp", expiresAt));
    return id;
  }

  public UUID insertExpired(UUID tenantId, UUID userId, OffsetDateTime pastExpires) {
    return insertLive(tenantId, userId, pastExpires);
  }

  public UUID insertRevoked(UUID tenantId, UUID userId, OffsetDateTime expiresAt) {
    UUID id = UUID.randomUUID();
    OffsetDateTime now = OffsetDateTime.now();
    admin.update(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, "
            + " revoked_at, revoked_reason, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :exp, "
            + "        :now, 'LOGOUT', :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("exp", expiresAt));
    return id;
  }

  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }
}
```

⚠️ `RevokedReason` 상수 (`'LOGOUT'`) 확인:
Run: `grep -n "enum RevokedReason\|LOGOUT\|ADMIN_FORCED" server/src/main/java/com/crosscert/passkey/auth/jwt/domain/RevokedReason.java`
실제 enum 값에 `LOGOUT`이 없으면 (예: `USER_LOGOUT`이라면) seed의 문자열도 맞춰 변경.

- [ ] **Step 4: 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.auth.RefreshTokenRepositoryPagedSliceTest" --console=plain 2>&1 | tail -15`
Expected: COMPILE FAILURE — `findActiveByTenantUserId`, `findAllByTenantUserId(Pageable)`, `countActiveByTenantUserId` 없음.

---

### Task 7: `RefreshTokenRepository`에 paged + count 메서드 구현

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenRepository.java`

- [ ] **Step 1: 메서드 추가**

기존 `findByIdAndTenantUserId` 옆에 추가:

```java
  /** Active = not revoked AND not expired. Sorted by issuedAt desc. */
  @Query("SELECT r FROM RefreshToken r "
      + "WHERE r.tenantUserId = :userId AND r.revokedAt IS NULL AND r.expiresAt > :now "
      + "ORDER BY r.issuedAt DESC")
  Page<RefreshToken> findActiveByTenantUserId(
      @Param("userId") UUID tenantUserId,
      @Param("now") OffsetDateTime now,
      Pageable pageable);

  /** All states for the user, sorted by issuedAt desc. Used by the admin Sessions tab "All" filter. */
  @Query("SELECT r FROM RefreshToken r WHERE r.tenantUserId = :userId ORDER BY r.issuedAt DESC")
  Page<RefreshToken> findAllByTenantUserId(@Param("userId") UUID tenantUserId, Pageable pageable);

  /** Active count for the admin summary. */
  @Query("SELECT COUNT(r) FROM RefreshToken r "
      + "WHERE r.tenantUserId = :userId AND r.revokedAt IS NULL AND r.expiresAt > :now")
  long countActiveByTenantUserId(
      @Param("userId") UUID tenantUserId, @Param("now") OffsetDateTime now);
```

`import org.springframework.data.domain.{Page, Pageable};`도 필요 시 추가.

- [ ] **Step 2: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.auth.RefreshTokenRepositoryPagedSliceTest" --console=plain`
Expected: BUILD SUCCESSFUL, 2 tests passed

- [ ] **Step 3: spotless + 커밋**

```bash
cd server && ./gradlew spotlessApply --console=plain
cd ..
git add server/src/main/java/com/crosscert/passkey/auth/jwt/repository/RefreshTokenRepository.java \
        server/src/test/java/com/crosscert/passkey/slice/auth/RefreshTokenRepositoryPagedSliceTest.java \
        server/src/test/java/com/crosscert/passkey/integration/support/RefreshTokenSeed.java
git commit -m "feat(auth): paged findActive/findAll + countActive on RefreshTokenRepository for admin sessions tab"
```

---

### Task 8: `AdminEndUserController` paged credentials/refresh-tokens + detail 변경 — failing slice test

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/slice/admin/AdminEndUserControllerPagedSliceTest.java` (신규)
- Modify (Task 9에서): `server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java`

- [ ] **Step 1: failing slice test 작성**

```java
package com.crosscert.passkey.slice.admin;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.controller.AdminEndUserController;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.admin.security.AdminRole;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.CredentialSeed;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

class AdminEndUserControllerPagedSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired MockMvc mvc;
  @Autowired TenantSeed seed;
  @Autowired CredentialSeed credentialSeed;
  @Autowired RefreshTokenSeed tokenSeed;

  @Test
  @Transactional
  void detail_returnsCountsObjectInsteadOfInlineCredentials() throws Exception {
    UUID tenant = seed.createTenant("d-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.SUSPENDED);
    tokenSeed.insertLive(tenant, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));
    loginAsTenantAdmin(tenant);

    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}", tenant, user))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.credentials.active").value(1))
        .andExpect(jsonPath("$.data.credentials.suspended").value(1))
        .andExpect(jsonPath("$.data.credentials.revoked").value(0))
        .andExpect(jsonPath("$.data.sessions.active").value(1))
        // OLD field should be gone
        .andExpect(jsonPath("$.data.credentials[*]").doesNotExist());
  }

  @Test
  @Transactional
  void credentials_pagedReturnsAaguidLabel() throws Exception {
    UUID tenant = seed.createTenant("c-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    loginAsTenantAdmin(tenant);

    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}/credentials?page=0&size=10",
            tenant, user))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)))
        .andExpect(jsonPath("$.data.content[0].aaguid.value").exists())
        .andExpect(jsonPath("$.data.content[0].aaguid.label").exists())
        .andExpect(jsonPath("$.data.content[0].aaguid.fromMds").isBoolean());
  }

  @Test
  @Transactional
  void refreshTokens_defaultStatusActive_excludesRevoked() throws Exception {
    UUID tenant = seed.createTenant("t-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));
    loginAsTenantAdmin(tenant);

    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens?page=0&size=10",
            tenant, user))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(1)));
  }

  @Test
  @Transactional
  void refreshTokens_statusAll_includesRevoked() throws Exception {
    UUID tenant = seed.createTenant("ta-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));
    loginAsTenantAdmin(tenant);

    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens"
                + "?status=all&page=0&size=10",
            tenant, user))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)));
  }

  // ---- helpers ------------------------------------------------------------

  private static void loginAsTenantAdmin(UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, AdminRole.RP_ADMIN, "ops@local", "Ops");
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities()));
  }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.AdminEndUserControllerPagedSliceTest" --console=plain 2>&1 | tail -25`
Expected: 4 tests FAIL (detail 응답 형식 다르고, paged endpoint들이 404 또는 mapping 없음)

---

### Task 9: `AdminEndUserController` 수정 + paged endpoints 추가

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java`

- [ ] **Step 1: `EndUserDetailView` record + summary records 재정의 + paged response records 추가**

`AdminEndUserController` 클래스 내부 (기존 records 자리에) — 기존 `EndUserDetailView` 교체:

```java
  /** One row of the end-user list. */
  public record EndUserView(
      UUID id,
      String externalId,
      String displayName,
      long activeCredentialCount,
      OffsetDateTime createdAt,
      OffsetDateTime updatedAt) {
    static EndUserView from(EndUserRow r) {
      return new EndUserView(
          r.getId(), r.getExternalId(), r.getDisplayName(),
          r.getActiveCredentialCount(), r.getCreatedAt(), r.getUpdatedAt());
    }
  }

  public record CredentialCounts(long active, long suspended, long revoked) {}
  public record SessionCounts(long active) {}

  /** End-user metadata + summary counts. No inline credentials — use the paged endpoint. */
  public record EndUserDetailView(
      UUID id,
      String externalId,
      String displayName,
      OffsetDateTime createdAt,
      OffsetDateTime updatedAt,
      CredentialCounts credentials,
      SessionCounts sessions,
      OffsetDateTime lastActivityAt) {}

  /** One row of the credentials paged endpoint. */
  public record UserCredentialItemView(
      UUID id,
      String credentialIdShort,
      AaguidLabel aaguid,
      CredentialStatus status,
      String suspendedReason,
      String nickname,
      OffsetDateTime createdAt,
      OffsetDateTime lastUsedAt) {}

  /** One row of the refresh-tokens paged endpoint. */
  public record RefreshTokenView(
      UUID id,
      OffsetDateTime issuedAt,
      OffsetDateTime expiresAt,
      String clientIp,
      String userAgent,
      OffsetDateTime revokedAt,
      RevokedReason revokedReason) {}
```

import 추가:

```java
import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.metadata.AaguidLabel;
import com.crosscert.passkey.credential.metadata.AaguidLabelResolver;
import java.time.ZoneOffset;
import java.util.HexFormat;
```

- [ ] **Step 2: 의존성 필드 추가 + 생성자에 등장**

기존:
```java
private final TenantUserRepository tenantUserRepo;
private final CredentialRepository credentialRepo;
private final AuditAggregationService auditAgg;
```

다음으로 교체:
```java
private final TenantUserRepository tenantUserRepo;
private final CredentialRepository credentialRepo;
private final RefreshTokenRepository refreshTokenRepo;
private final AuditAggregationService auditAgg;
private final AaguidLabelResolver aaguidLabelResolver;
```

(`@RequiredArgsConstructor`라 생성자 자동 생성, 필드만 추가하면 됨.)

- [ ] **Step 3: `detail` 메서드 본문 교체**

```java
  @GetMapping("/{tenantUserId}")
  @Transactional(readOnly = true)
  @Operation(summary = "Get one end-user with summary counts and last-activity")
  public ApiResponse<EndUserDetailView> detail(
      @PathVariable UUID tenantId, @PathVariable UUID tenantUserId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantUser user = requireUser(tenantId, tenantUserId);

    CredentialCounts cc = new CredentialCounts(
        credentialRepo.countByTenantUserIdAndStatus(tenantUserId, CredentialStatus.ACTIVE),
        credentialRepo.countByTenantUserIdAndStatus(tenantUserId, CredentialStatus.SUSPENDED),
        credentialRepo.countByTenantUserIdAndStatus(tenantUserId, CredentialStatus.REVOKED));
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    SessionCounts sc = new SessionCounts(refreshTokenRepo.countActiveByTenantUserId(tenantUserId, now));

    OffsetDateTime auditLast =
        auditAgg.lastEventForSubject(tenantId, tenantUserId.toString()).orElse(null);
    // Inline last-credential-lastUsedAt fold is no longer cheap (credentials aren't loaded);
    // omit the credential-side max and rely on audit's last event timestamp instead. UI shows
    // "—" when null, same as before.
    return ApiResponse.ok(
        new EndUserDetailView(
            user.getId(),
            user.getExternalId(),
            user.getDisplayName(),
            user.getCreatedAt(),
            user.getUpdatedAt(),
            cc,
            sc,
            auditLast));
  }

  private TenantUser requireUser(UUID tenantId, UUID tenantUserId) {
    TenantUser user =
        tenantUserRepo
            .findById(tenantUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    if (!user.getTenantId().equals(tenantId)) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "tenantUserId does not belong to the path tenant");
    }
    return user;
  }
```

기존의 `maxNullable` 헬퍼 + 미사용 import는 spotless가 알아서 정리하므로 일단 두고 다음 step에서 제거.

- [ ] **Step 4: paged endpoints 2개 추가 + import 정리**

`detail` 메서드 다음에 추가:

```java
  @GetMapping("/{tenantUserId}/credentials")
  @Transactional(readOnly = true)
  @Operation(summary = "Paged credentials for one end-user (with AAGUID label)")
  public ApiResponse<PageResponse<UserCredentialItemView>> credentials(
      @PathVariable UUID tenantId,
      @PathVariable UUID tenantUserId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {
    AdminAuthz.requireTenantAccess(tenantId);
    requireUser(tenantId, tenantUserId);
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    return ApiResponse.ok(
        PageResponse.from(
            credentialRepo.findAllByTenantUserId(tenantUserId, pageable).map(this::toCredentialRow)));
  }

  @GetMapping("/{tenantUserId}/refresh-tokens")
  @Transactional(readOnly = true)
  @Operation(summary = "Paged refresh tokens for one end-user")
  public ApiResponse<PageResponse<RefreshTokenView>> refreshTokens(
      @PathVariable UUID tenantId,
      @PathVariable UUID tenantUserId,
      @RequestParam(defaultValue = "active") String status,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {
    AdminAuthz.requireTenantAccess(tenantId);
    requireUser(tenantId, tenantUserId);
    Pageable pageable = PageRequest.of(page, size); // ordering enforced by @Query
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    var pageResult =
        "all".equalsIgnoreCase(status)
            ? refreshTokenRepo.findAllByTenantUserId(tenantUserId, pageable)
            : refreshTokenRepo.findActiveByTenantUserId(tenantUserId, now, pageable);
    return ApiResponse.ok(PageResponse.from(pageResult.map(AdminEndUserController::toRefreshTokenRow)));
  }

  private UserCredentialItemView toCredentialRow(Credential c) {
    String idShort =
        c.getCredentialId() == null
            ? null
            : c.getCredentialId().length() <= 8
                ? c.getCredentialId()
                : c.getCredentialId().substring(0, 8);
    AaguidLabel label = aaguidLabelResolver.resolve(c.getAaguid());
    return new UserCredentialItemView(
        c.getId(),
        idShort,
        label,
        c.getStatus(),
        c.getSuspendedReason() == null ? null : c.getSuspendedReason().name(),
        c.getNickname(),
        c.getCreatedAt(),
        c.getLastUsedAt());
  }

  private static RefreshTokenView toRefreshTokenRow(RefreshToken r) {
    return new RefreshTokenView(
        r.getId(),
        r.getIssuedAt(),
        r.getExpiresAt(),
        r.getClientIp(),
        r.getUserAgent(),
        r.getRevokedAt(),
        r.getRevokedReason());
  }
```

⚠️ `Credential` getter들(`getCredentialId`, `getAaguid`, `getSuspendedReason`, `getNickname`, `getLastUsedAt`) 시그니처는 production code에서 확인:
Run: `grep -n "@Column\|private.*[A-Z]" server/src/main/java/com/crosscert/passkey/credential/domain/Credential.java | head -30`
시그니처가 다르면 toCredentialRow 본문 그에 맞춰 조정.

- [ ] **Step 5: 미사용 import / private 헬퍼 정리**

`spotless` 적용:
Run: `cd server && ./gradlew spotlessApply --console=plain`
이후 `AdminEndUserController` 안에 더이상 사용 안 되는 `CredentialView` import / `maxNullable` 헬퍼 수동 제거:
Run: `grep -n "CredentialView\|maxNullable" server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java`
출력된 라인의 import / private static method를 Edit 도구로 제거.

- [ ] **Step 6: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.AdminEndUserControllerPagedSliceTest" --console=plain`
Expected: BUILD SUCCESSFUL, 4 tests passed

- [ ] **Step 7: 기존 controller 슬라이스 테스트 회귀 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.*" --console=plain 2>&1 | tail -15`
Expected: 모든 admin slice test 통과 (기존 `AdminEndUserController` detail 테스트가 있으면 응답 형식 변경 때문에 깨질 가능성 — 그 경우 그 테스트도 새 응답 형식으로 함께 수정해야 함. 깨지면 Edit 도구로 같이 수정 후 재실행)

- [ ] **Step 8: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java \
        server/src/test/java/com/crosscert/passkey/slice/admin/AdminEndUserControllerPagedSliceTest.java
git commit -m "feat(admin)!: EndUserDetailView counts-only + paged credentials/refresh-tokens endpoints

BREAKING: EndUserDetailView.credentials field is now CredentialCounts
object, not List<CredentialView>. The credentials list moves to a new
paged endpoint GET /users/{id}/credentials with AAGUID label objects.
Admin console (only consumer) is updated in the same series of PRs."
```

---

### Task 10: `AdminRefreshTokenController` 신규 — failing slice test

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/slice/admin/AdminRefreshTokenControllerSliceTest.java` (신규)
- Create (Task 11에서): `server/src/main/java/com/crosscert/passkey/admin/controller/AdminRefreshTokenController.java`

- [ ] **Step 1: failing slice test 작성**

```java
package com.crosscert.passkey.slice.admin;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.admin.security.AdminRole;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

class AdminRefreshTokenControllerSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired MockMvc mvc;
  @Autowired TenantSeed seed;
  @Autowired RefreshTokenSeed tokenSeed;
  @Autowired RefreshTokenRepository repo;

  @Test
  @Transactional
  void delete_revokesActive_returnsAlreadyRevokedFalse() throws Exception {
    UUID tenant = seed.createTenant("rd-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    UUID tokenId = tokenSeed.insertLive(tenant, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));
    loginAsTenantAdmin(tenant);

    mvc.perform(delete("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
            tenant, user, tokenId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.alreadyRevoked").value(false));

    assertTokenRevoked(tokenId);
  }

  @Test
  @Transactional
  void delete_secondCallIsIdempotent_returnsAlreadyRevokedTrue() throws Exception {
    UUID tenant = seed.createTenant("idem-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    UUID tokenId = tokenSeed.insertRevoked(tenant, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));
    loginAsTenantAdmin(tenant);

    mvc.perform(delete("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
            tenant, user, tokenId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.alreadyRevoked").value(true));
  }

  @Test
  @Transactional
  void delete_tokenBelongsToDifferentUser_returns404() throws Exception {
    UUID tenant = seed.createTenant("mismatch-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenant, "ua-" + UUID.randomUUID());
    UUID userB = seed.createUser(tenant, "ub-" + UUID.randomUUID());
    UUID tokenOfA = tokenSeed.insertLive(tenant, userA, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));
    loginAsTenantAdmin(tenant);

    mvc.perform(delete("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
            tenant, userB, tokenOfA))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("C003"));
  }

  @Test
  @Transactional
  void delete_unknownToken_returns404() throws Exception {
    UUID tenant = seed.createTenant("u-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    loginAsTenantAdmin(tenant);

    mvc.perform(delete("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
            tenant, user, UUID.randomUUID()))
        .andExpect(status().isNotFound());
  }

  @Test
  @Transactional
  void delete_wrongTenantAdmin_returns403() throws Exception {
    UUID tenantA = seed.createTenant("tA-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("tB-" + UUID.randomUUID());
    UUID user = seed.createUser(tenantA, "u-" + UUID.randomUUID());
    UUID tokenId = tokenSeed.insertLive(tenantA, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));
    loginAsTenantAdmin(tenantB);

    mvc.perform(delete("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
            tenantA, user, tokenId))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));
  }

  private void assertTokenRevoked(UUID tokenId) {
    org.assertj.core.api.Assertions.assertThat(repo.findById(tokenId))
        .isPresent()
        .get()
        .extracting(t -> t.getRevokedAt() != null)
        .isEqualTo(Boolean.TRUE);
  }

  private static void loginAsTenantAdmin(UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, AdminRole.RP_ADMIN, "ops@local", "Ops");
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities()));
  }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.AdminRefreshTokenControllerSliceTest" --console=plain 2>&1 | tail -25`
Expected: 모든 test FAIL (404 because endpoint doesn't exist)

---

### Task 11: `AdminRefreshTokenController` 구현

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/admin/controller/AdminRefreshTokenController.java`

- [ ] **Step 1: controller 작성**

```java
package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Per-session revoke. Siblings: {@code AdminUserSessionController.forceLogout} mass-revokes,
 * {@code AdminEndUserController.refreshTokens} lists. This one removes a single device while
 * leaving the user's other sessions alone — the "kick one device" lever RPs were asking for.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/users/{tenantUserId}/refresh-tokens")
@RequiredArgsConstructor
@Tag(name = "Admin · Refresh Tokens", description = "Per-session revoke for a single user's token.")
public class AdminRefreshTokenController {

  private final TenantUserRepository tenantUserRepo;
  private final RefreshTokenRepository refreshTokenRepo;
  private final AuditService auditService;

  public record RevokeResult(boolean alreadyRevoked) {}

  @DeleteMapping("/{tokenId}")
  @Transactional
  @Operation(
      summary = "Revoke a single refresh token",
      description =
          "Idempotent — second call on an already-revoked token returns alreadyRevoked=true. "
              + "Audit log REFRESH_TOKEN_REVOKED is written on the first revoke only.")
  public ApiResponse<RevokeResult> revoke(
      @PathVariable UUID tenantId,
      @PathVariable UUID tenantUserId,
      @PathVariable UUID tokenId) {
    AdminAuthz.requireTenantAccess(tenantId);
    requireUser(tenantId, tenantUserId);
    RefreshToken token =
        refreshTokenRepo
            .findByIdAndTenantUserId(tokenId, tenantUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    if (token.isRevoked()) {
      return ApiResponse.ok(new RevokeResult(true));
    }
    token.revoke(RevokedReason.ADMIN_FORCED);
    auditService.append(
        AuditEventType.REFRESH_TOKEN_REVOKED,
        ActorType.ADMIN,
        AdminAuthz.currentPrincipal().adminId().toString(),
        "REFRESH_TOKEN",
        tokenId.toString(),
        Map.of("tenantUserId", tenantUserId.toString(), "reason", "ADMIN_FORCED"));
    log.info(
        "admin.refreshToken.revoked tenantId={} tenantUserId={} tokenId={}",
        tenantId,
        tenantUserId,
        tokenId);
    return ApiResponse.ok(new RevokeResult(false));
  }

  private TenantUser requireUser(UUID tenantId, UUID tenantUserId) {
    TenantUser user =
        tenantUserRepo
            .findById(tenantUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    if (!user.getTenantId().equals(tenantId)) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "tenantUserId does not belong to the path tenant");
    }
    return user;
  }
}
```

- [ ] **Step 2: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.AdminRefreshTokenControllerSliceTest" --console=plain`
Expected: BUILD SUCCESSFUL, 5 tests passed

- [ ] **Step 3: spotless + 커밋**

```bash
cd server && ./gradlew spotlessApply --console=plain
cd ..
git add server/src/main/java/com/crosscert/passkey/admin/controller/AdminRefreshTokenController.java \
        server/src/test/java/com/crosscert/passkey/slice/admin/AdminRefreshTokenControllerSliceTest.java
git commit -m "feat(admin): DELETE refresh-tokens/{id} — single-session revoke with idempotent semantics + audit"
```

---

### Task 12: Integration test (end-to-end through 5 endpoints)

**Files:**
- Test: `server/src/test/java/com/crosscert/passkey/integration/admin/AdminUserViewIntegrationTest.java` (신규)

- [ ] **Step 1: 통합 시나리오 test 작성**

```java
package com.crosscert.passkey.integration.admin;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.admin.security.AdminRole;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.CredentialSeed;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

class AdminUserViewIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired MockMvc mvc;
  @Autowired TenantSeed seed;
  @Autowired CredentialSeed credentialSeed;
  @Autowired RefreshTokenSeed tokenSeed;

  @Test
  void fullFlow_listDetailCredentialsTokensRevokeReread() throws Exception {
    // Two tenants; ensure VPD isolation by trying to read tenantA from tenantB admin at the end.
    UUID tenantA = seed.createTenant("ivA-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("ivB-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenantA, "alice-" + UUID.randomUUID());
    seed.createUser(tenantA, "bob-" + UUID.randomUUID());

    credentialSeed.create(tenantA, userA, CredentialStatus.ACTIVE);
    credentialSeed.create(tenantA, userA, CredentialStatus.SUSPENDED);
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    UUID activeToken = tokenSeed.insertLive(tenantA, userA, now.plusDays(7));
    tokenSeed.insertLive(tenantA, userA, now.plusDays(7));

    loginAsTenantAdmin(tenantA);

    // 1) list — paged
    mvc.perform(get("/api/v1/admin/tenants/{tid}/users?page=0&size=10", tenantA))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)));

    // 2) detail — counts only, no inline credentials
    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}", tenantA, userA))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.credentials.active").value(1))
        .andExpect(jsonPath("$.data.credentials.suspended").value(1))
        .andExpect(jsonPath("$.data.sessions.active").value(2));

    // 3) credentials page — AAGUID label present
    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}/credentials?page=0&size=10",
            tenantA, userA))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)))
        .andExpect(jsonPath("$.data.content[0].aaguid.fromMds").isBoolean());

    // 4) refresh-tokens page — default active
    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens?page=0&size=10",
            tenantA, userA))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)));

    // 5) revoke one
    mvc.perform(delete("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
            tenantA, userA, activeToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.alreadyRevoked").value(false));

    // 6) re-read active list — one less
    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens?page=0&size=10",
            tenantA, userA))
        .andExpect(jsonPath("$.data.content", hasSize(1)));

    // 7) cross-tenant isolation — tenantB admin can't read tenantA's user
    loginAsTenantAdmin(tenantB);
    mvc.perform(get("/api/v1/admin/tenants/{tid}/users/{uid}", tenantA, userA))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));
  }

  private static void loginAsTenantAdmin(UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, AdminRole.RP_ADMIN, "ops@local", "Ops");
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities()));
  }
}
```

- [ ] **Step 2: 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.admin.AdminUserViewIntegrationTest" --console=plain`
Expected: BUILD SUCCESSFUL, 1 test passed

- [ ] **Step 3: 전체 check (ArchUnit + 회귀)**

Run: `cd server && ./gradlew check --console=plain 2>&1 | tail -10`
Expected: BUILD SUCCESSFUL. 실패하는 케이스 있으면 stop 후 분석.

- [ ] **Step 4: 커밋**

```bash
git add server/src/test/java/com/crosscert/passkey/integration/admin/AdminUserViewIntegrationTest.java
git commit -m "test(admin): end-to-end integration for user view (list → detail → credentials → tokens → revoke → cross-tenant)"
```

---

## Phase 2: 클라이언트 — Credentials 탭 (2주차)

### Task 13: TS 타입 정의 + apiHelpers — 신규 응답 타입 정의

**Files:**
- Modify: `admin/src/types/api.ts`

- [ ] **Step 1: 기존 `EndUserDetailView` + `CredentialView` import 위치 확인**

Run: `grep -n "EndUserDetailView\|CredentialView" admin/src/types/api.ts`
Expected: 라인 번호. 기존 `EndUserDetailView`의 `credentials: CredentialView[]` 필드 변경 대상.

- [ ] **Step 2: `EndUserDetailView` 교체 + 신규 타입 추가**

`admin/src/types/api.ts`의 기존 `EndUserDetailView` 인터페이스를 다음으로 교체:

```ts
export interface CredentialCounts {
  active: number;
  suspended: number;
  revoked: number;
}

export interface SessionCounts {
  active: number;
}

export interface EndUserDetailView {
  id: string;
  externalId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
  credentials: CredentialCounts; // CHANGED: was CredentialView[]
  sessions: SessionCounts; // NEW
  lastActivityAt: string | null;
}

export interface AaguidLabelDto {
  aaguid: string | null;
  displayName: string;
  fromMds: boolean;
}

export interface UserCredentialItemView {
  id: string;
  credentialIdShort: string | null;
  aaguid: AaguidLabelDto;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  suspendedReason: string | null;
  nickname: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface RefreshTokenView {
  id: string;
  issuedAt: string;
  expiresAt: string;
  clientIp: string | null;
  userAgent: string | null;
  revokedAt: string | null;
  revokedReason: string | null;
}

export interface RevokeRefreshTokenResult {
  alreadyRevoked: boolean;
}
```

- [ ] **Step 3: 타입체크**

Run: `cd admin && npm run typecheck`
Expected: 컴파일 에러 — `UserDetailPage.tsx`가 `data.credentials` (List)를 사용 중이라 type mismatch. 정상(다음 task에서 처리).

- [ ] **Step 4: 커밋 (typecheck 깨진 상태이므로 단독 커밋 안 함 — Task 17 끝에 함께)**

대신 노트 — Phase 2 끝에 한 번에 commit.

---

### Task 14: `AaguidLabel` 컴포넌트 + Vitest

**Files:**
- Create: `admin/src/components/AaguidLabel.tsx`
- Create: `admin/src/components/AaguidLabel.test.tsx`

- [ ] **Step 1: failing test 작성**

```tsx
// admin/src/components/AaguidLabel.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AaguidLabel } from "./AaguidLabel";

describe("AaguidLabel", () => {
  it("renders MDS label without 미등록 badge when fromMds=true", () => {
    render(
      <AaguidLabel
        aaguid={{ aaguid: "11111111-1111-1111-1111-111111111111", displayName: "YubiKey 5C", fromMds: true }}
      />,
    );
    expect(screen.getByText("YubiKey 5C")).toBeInTheDocument();
    expect(screen.queryByText("미등록")).not.toBeInTheDocument();
  });

  it("renders raw uuid with 미등록 badge when fromMds=false", () => {
    render(
      <AaguidLabel
        aaguid={{ aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", displayName: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", fromMds: false }}
      />,
    );
    expect(screen.getByText(/ea9b8d66/)).toBeInTheDocument();
    expect(screen.getByText("미등록")).toBeInTheDocument();
  });

  it("renders 'unknown' for null aaguid", () => {
    render(
      <AaguidLabel
        aaguid={{ aaguid: null, displayName: "unknown", fromMds: false }}
      />,
    );
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });
});
```

⚠️ `@testing-library/react` 의존성 확인:
Run: `grep "@testing-library/react" admin/package.json`
없으면 기존 vitest 셋업에 `jsdom` + `@testing-library/react` 추가 필요 — 일단 있다고 가정 (admin/ 이미 Vitest 셋업).

Run: `cd admin && npm run test -- --run AaguidLabel`
Expected: COMPILE FAIL — 컴포넌트 없음.

- [ ] **Step 2: 컴포넌트 구현**

```tsx
// admin/src/components/AaguidLabel.tsx
import * as React from "react";
import { Badge } from "@/components/ui/badge";
import type { AaguidLabelDto } from "@/types/api";

interface Props {
  aaguid: AaguidLabelDto;
  className?: string;
}

/**
 * Renders the AAGUID label. When fromMds=true the MDS description is shown plain.
 * When false (MDS miss or no blob loaded), the raw UUID is shown with a "미등록" badge so
 * operators can tell certified-FIDO authenticators from platform/community ones.
 */
export function AaguidLabel({ aaguid, className }: Props) {
  return (
    <span className={className ?? "inline-flex items-center gap-1.5"}>
      <span className={aaguid.fromMds ? "" : "font-mono text-xs"}>{aaguid.displayName}</span>
      {!aaguid.fromMds && aaguid.aaguid !== null && (
        <Badge variant="outline" className="text-xs">
          미등록
        </Badge>
      )}
    </span>
  );
}
```

⚠️ `Badge` 컴포넌트의 `variant="outline"` 지원 여부 확인:
Run: `grep -n "variant.*outline\|outline.*variant" admin/src/components/ui/badge.tsx`
없으면 그냥 `variant` 생략 (`<Badge className="text-xs">`).

- [ ] **Step 3: 통과 확인**

Run: `cd admin && npm run test -- --run AaguidLabel`
Expected: 3 tests passed

---

### Task 15: `ConfirmDialog` 컴포넌트 (AlertDialog 의존성 회피용)

**Files:**
- Create: `admin/src/components/ConfirmDialog.tsx`

- [ ] **Step 1: 컴포넌트 작성**

```tsx
// admin/src/components/ConfirmDialog.tsx
import * as React from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface Props {
  open: boolean;
  title: string;
  description?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  onConfirm: () => void;
  onOpenChange: (open: boolean) => void;
  busy?: boolean;
}

/**
 * Minimal Dialog-based confirm modal. We avoid pulling in @radix-ui/react-alert-dialog —
 * the existing Dialog suffices for confirm flows (revoke session, force logout, etc).
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "확인",
  cancelLabel = "취소",
  destructive = false,
  onConfirm,
  onOpenChange,
  busy = false,
}: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button
            variant={destructive ? "destructive" : "default"}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? "처리 중…" : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

⚠️ `Button` `variant="destructive"` 지원 여부 확인:
Run: `grep -n "destructive" admin/src/components/ui/button.tsx`
없으면 `className="bg-red-600 hover:bg-red-700"` 같은 인라인 처리.

- [ ] **Step 2: 컴파일 통과 확인**

Run: `cd admin && npm run typecheck`
Expected: ConfirmDialog 본인 컴파일 OK. (UserDetailPage 에러는 아직 남아있음 — Task 17 후 해결)

---

### Task 16: Credentials 탭 패널 + 데이터 훅

**Files:**
- Create: `admin/src/pages/tenant/user-detail/CredentialsTabPanel.tsx`

- [ ] **Step 1: 패널 작성**

```tsx
// admin/src/pages/tenant/user-detail/CredentialsTabPanel.tsx
import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { AaguidLabel } from "@/components/AaguidLabel";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { apiGet, apiDelete, apiPost, PasskeyAdminError } from "@/lib/api";
import type { PageResponse, UserCredentialItemView } from "@/types/api";
import { useToast } from "@/hooks/use-toast";
import { formatDateTime } from "@/lib/format";

const size = 20;

function statusBadgeVariant(s: UserCredentialItemView["status"]) {
  switch (s) {
    case "ACTIVE": return "default";
    case "SUSPENDED": return "secondary";
    case "REVOKED": return "outline";
  }
}

interface Props {
  tenantId: string;
  tenantUserId: string;
}

export function CredentialsTabPanel({ tenantId, tenantUserId }: Props) {
  const [page, setPage] = React.useState(0);
  const qc = useQueryClient();
  const { toast } = useToast();
  const [confirmRow, setConfirmRow] = React.useState<UserCredentialItemView | null>(null);
  const [confirmAction, setConfirmAction] = React.useState<"revoke" | "unsuspend" | null>(null);

  const queryKey = ["userCredentials", tenantId, tenantUserId, page];
  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: () =>
      apiGet<PageResponse<UserCredentialItemView>>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/credentials?page=${page}&size=${size}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  const revoke = useMutation({
    mutationFn: (credentialId: string) =>
      apiDelete(`/api/v1/admin/tenants/${tenantId}/credentials/${credentialId}`),
    onSuccess: () => {
      toast({ variant: "success", title: "자격증명이 회수되었습니다." });
      qc.invalidateQueries({ queryKey: ["userCredentials", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      setConfirmRow(null); setConfirmAction(null);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const unsuspend = useMutation({
    mutationFn: (credentialId: string) =>
      apiPost<void>(`/api/v1/admin/tenants/${tenantId}/credentials/${credentialId}/unsuspend`),
    onSuccess: () => {
      toast({ variant: "success", title: "자격증명 정지가 해제되었습니다." });
      qc.invalidateQueries({ queryKey: ["userCredentials", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      setConfirmRow(null); setConfirmAction(null);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  if (isLoading) return <p>불러오는 중…</p>;
  const rows = data?.content ?? [];
  if (rows.length === 0) {
    return <EmptyState title="이 사용자에게는 등록된 자격증명이 없습니다." />;
  }

  return (
    <div className="space-y-3">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>AAGUID</TableHead>
            <TableHead>상태</TableHead>
            <TableHead>닉네임</TableHead>
            <TableHead>Credential ID</TableHead>
            <TableHead>마지막 사용</TableHead>
            <TableHead>등록</TableHead>
            <TableHead className="text-right">액션</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((c) => (
            <TableRow key={c.id}>
              <TableCell><AaguidLabel aaguid={c.aaguid} /></TableCell>
              <TableCell><Badge variant={statusBadgeVariant(c.status)}>{c.status}</Badge></TableCell>
              <TableCell>{c.nickname ?? "—"}</TableCell>
              <TableCell className="font-mono text-xs">{c.credentialIdShort ?? "—"}</TableCell>
              <TableCell>{c.lastUsedAt ? formatDateTime(c.lastUsedAt) : "—"}</TableCell>
              <TableCell>{formatDateTime(c.createdAt)}</TableCell>
              <TableCell className="text-right space-x-2">
                {c.status === "ACTIVE" && (
                  <Button size="sm" variant="outline"
                    onClick={() => { setConfirmRow(c); setConfirmAction("revoke"); }}>
                    회수
                  </Button>
                )}
                {c.status === "SUSPENDED" && (
                  <Button size="sm" variant="outline"
                    onClick={() => { setConfirmRow(c); setConfirmAction("unsuspend"); }}>
                    정지 해제
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <div className="flex items-center justify-between pt-2">
        <Button disabled={!data?.hasPrevious} onClick={() => setPage((p) => Math.max(0, p - 1))}>이전</Button>
        <span>{(data?.page ?? 0) + 1} / {data?.totalPages ?? 1}</span>
        <Button disabled={!data?.hasNext} onClick={() => setPage((p) => p + 1)}>다음</Button>
      </div>

      <ConfirmDialog
        open={confirmRow !== null}
        title={confirmAction === "revoke" ? "자격증명 회수" : "정지 해제"}
        description={
          confirmAction === "revoke"
            ? `${confirmRow?.nickname ?? confirmRow?.credentialIdShort}을(를) 회수합니다. 이 자격증명으로는 더 이상 로그인할 수 없습니다.`
            : `${confirmRow?.nickname ?? confirmRow?.credentialIdShort}의 정지를 해제합니다.`
        }
        destructive={confirmAction === "revoke"}
        confirmLabel={confirmAction === "revoke" ? "회수" : "해제"}
        busy={revoke.isPending || unsuspend.isPending}
        onConfirm={() => {
          if (!confirmRow) return;
          if (confirmAction === "revoke") revoke.mutate(confirmRow.id);
          else if (confirmAction === "unsuspend") unsuspend.mutate(confirmRow.id);
        }}
        onOpenChange={(o) => {
          if (!o) { setConfirmRow(null); setConfirmAction(null); }
        }}
      />
    </div>
  );
}
```

⚠️ 다음 의존 항목이 존재하는지 확인 (없으면 일부 import 조정):
Run: `grep -rn "export.*formatDateTime\|use-toast\|EmptyState" admin/src --include="*.tsx" --include="*.ts" | head -10`
- `formatDateTime` → `admin/src/lib/format.ts` 확인
- `useToast` → `admin/src/hooks/use-toast.ts` 또는 비슷한 경로
- `EmptyState` → `admin/src/components/EmptyState.tsx`

import 경로가 다르면 그에 맞춰 수정.

- [ ] **Step 2: 컴파일 통과 확인 (typecheck)**

Run: `cd admin && npm run typecheck 2>&1 | tail -10`
Expected: Credentials 탭 본인은 통과. (`UserDetailPage`는 아직 에러 — 다음 task에서)

---

### Task 17: `UserDetailPage` 탭 구조 리팩토링

**Files:**
- Modify: `admin/src/pages/tenant/UserDetailPage.tsx`

- [ ] **Step 1: 기존 `UserDetailPage.tsx` 전체 교체**

```tsx
import * as React from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/CopyButton";
import { apiGet } from "@/lib/api";
import type { EndUserDetailView } from "@/types/api";
import { formatDateTime, lastN } from "@/lib/format";
import { CredentialsTabPanel } from "./user-detail/CredentialsTabPanel";
import { SessionsTabPanel } from "./user-detail/SessionsTabPanel";

function Meta({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={mono ? "font-mono text-sm" : "text-sm"}>{value}</div>
    </div>
  );
}

export function UserDetailPage() {
  const { tenantId, tenantUserId } = useParams<{ tenantId: string; tenantUserId: string }>();
  const [search, setSearch] = useSearchParams();
  const tab = search.get("tab") === "sessions" ? "sessions" : "credentials";

  const { data, isLoading, isError } = useQuery({
    queryKey: ["endUser", tenantId, tenantUserId],
    queryFn: () =>
      apiGet<EndUserDetailView>(`/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}`),
    enabled: !!tenantId && !!tenantUserId,
  });

  if (isLoading) return <p>불러오는 중…</p>;
  if (isError || !data) return <EmptyState title="사용자를 찾을 수 없습니다." />;

  return (
    <div className="space-y-5">
      <Link to={`/tenants/${tenantId}/users`} className="inline-flex items-center gap-1 text-xs text-muted-foreground">
        <ChevronLeft className="h-3.5 w-3.5" /> 사용자 목록
      </Link>

      <PageHeader
        title={data.displayName ?? data.externalId}
        description={
          <span className="inline-flex items-center gap-1.5">
            External ID: <span className="font-mono">{data.externalId}</span>
            <CopyButton value={data.externalId} />
          </span>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Meta label="내부 ID" value={lastN(data.id, 8)} mono />
        <Meta
          label="자격증명"
          value={
            <span className="space-x-1.5">
              <Badge variant="default">ACTIVE {data.credentials.active}</Badge>
              <Badge variant="secondary">SUSPENDED {data.credentials.suspended}</Badge>
              <Badge variant="outline">REVOKED {data.credentials.revoked}</Badge>
            </span>
          }
        />
        <Meta label="활성 세션" value={data.sessions.active} />
        <Meta
          label="최근 활동"
          value={data.lastActivityAt ? formatDateTime(data.lastActivityAt) : "—"}
        />
      </div>

      <Tabs
        value={tab}
        onValueChange={(v) => {
          const next = new URLSearchParams(search);
          next.set("tab", v);
          setSearch(next, { replace: true });
        }}
      >
        <TabsList>
          <TabsTrigger value="credentials">Credentials</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
        </TabsList>
        <TabsContent value="credentials" className="pt-3">
          <CredentialsTabPanel tenantId={tenantId!} tenantUserId={tenantUserId!} />
        </TabsContent>
        <TabsContent value="sessions" className="pt-3">
          <SessionsTabPanel tenantId={tenantId!} tenantUserId={tenantUserId!} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

⚠️ Sessions 탭은 다음 phase에서 만듦 — 일단 placeholder 컴포넌트로 컴파일 통과 확보:

Create: `admin/src/pages/tenant/user-detail/SessionsTabPanel.tsx`:

```tsx
import * as React from "react";

interface Props {
  tenantId: string;
  tenantUserId: string;
}

export function SessionsTabPanel({ tenantId, tenantUserId }: Props) {
  return (
    <p className="text-sm text-muted-foreground">
      Sessions 탭은 Phase 3에서 구현됩니다. ({tenantId}/{tenantUserId})
    </p>
  );
}
```

(이 placeholder는 Task 19에서 실제 구현으로 교체.)

- [ ] **Step 2: typecheck + build**

Run: `cd admin && npm run typecheck && npm run build 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: 단위 테스트**

Run: `cd admin && npm run test -- --run`
Expected: 모든 vitest 통과

- [ ] **Step 4: 커밋 (Phase 2 묶음)**

```bash
git add admin/src/types/api.ts \
        admin/src/components/AaguidLabel.tsx \
        admin/src/components/AaguidLabel.test.tsx \
        admin/src/components/ConfirmDialog.tsx \
        admin/src/pages/tenant/UserDetailPage.tsx \
        admin/src/pages/tenant/user-detail/CredentialsTabPanel.tsx \
        admin/src/pages/tenant/user-detail/SessionsTabPanel.tsx
git commit -m "feat(admin): user-detail page tab structure + Credentials tab with AAGUID label + actions"
```

---

## Phase 3: Sessions 탭 + E2E (3주차)

### Task 18: Sessions 탭 패널 작성

**Files:**
- Modify: `admin/src/pages/tenant/user-detail/SessionsTabPanel.tsx`

- [ ] **Step 1: placeholder → 실제 구현으로 교체**

```tsx
import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { Segmented } from "@/components/Segmented";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { apiGet, apiDelete, apiPost, PasskeyAdminError } from "@/lib/api";
import type { PageResponse, RefreshTokenView, RevokeRefreshTokenResult } from "@/types/api";
import { useToast } from "@/hooks/use-toast";
import { formatDateTime, lastN } from "@/lib/format";

const size = 20;

interface Props {
  tenantId: string;
  tenantUserId: string;
}

type StatusFilter = "active" | "all";

export function SessionsTabPanel({ tenantId, tenantUserId }: Props) {
  const [page, setPage] = React.useState(0);
  const [statusFilter, setStatusFilter] = React.useState<StatusFilter>("active");
  const [confirmId, setConfirmId] = React.useState<string | null>(null);
  const [logoutAllOpen, setLogoutAllOpen] = React.useState(false);
  const qc = useQueryClient();
  const { toast } = useToast();

  React.useEffect(() => setPage(0), [statusFilter]);

  const queryKey = ["userRefreshTokens", tenantId, tenantUserId, page, statusFilter];
  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: () =>
      apiGet<PageResponse<RefreshTokenView>>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/refresh-tokens`
          + `?status=${statusFilter}&page=${page}&size=${size}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  const revokeOne = useMutation({
    mutationFn: (tokenId: string) =>
      apiDelete<RevokeRefreshTokenResult>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/refresh-tokens/${tokenId}`,
      ),
    onSuccess: (res) => {
      toast({
        variant: res?.alreadyRevoked ? "default" : "success",
        title: res?.alreadyRevoked ? "이미 회수된 세션입니다." : "세션이 회수되었습니다.",
      });
      qc.invalidateQueries({ queryKey: ["userRefreshTokens", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      setConfirmId(null);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const logoutAll = useMutation({
    mutationFn: () =>
      apiPost<{ revokedCount: number }>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/logout-all`,
      ),
    onSuccess: (res) => {
      toast({
        variant: "success",
        title: `${res?.revokedCount ?? 0}개 세션이 회수되었습니다.`,
      });
      qc.invalidateQueries({ queryKey: ["userRefreshTokens", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      setLogoutAllOpen(false);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const rows = data?.content ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <Segmented
          value={statusFilter}
          onChange={(v) => setStatusFilter(v as StatusFilter)}
          options={[
            { value: "active", label: "활성만" },
            { value: "all", label: "전체" },
          ]}
        />
        <Button variant="destructive" onClick={() => setLogoutAllOpen(true)}>
          모두 로그아웃
        </Button>
      </div>

      {isLoading ? (
        <p>불러오는 중…</p>
      ) : rows.length === 0 ? (
        <EmptyState
          title={statusFilter === "active" ? "활성 세션이 없습니다." : "이 사용자의 세션 기록이 없습니다."}
        />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>발급</TableHead>
                <TableHead>만료</TableHead>
                <TableHead>Client</TableHead>
                <TableHead>상태</TableHead>
                <TableHead className="text-right">액션</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((t) => {
                const revoked = t.revokedAt !== null;
                return (
                  <TableRow key={t.id}>
                    <TableCell>{formatDateTime(t.issuedAt)}</TableCell>
                    <TableCell>{formatDateTime(t.expiresAt)}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {t.clientIp ?? "—"}
                      {t.userAgent ? ` · ${lastN(t.userAgent, 24)}` : ""}
                    </TableCell>
                    <TableCell>
                      {revoked
                        ? <Badge variant="outline">{t.revokedReason ?? "REVOKED"}</Badge>
                        : <Badge variant="default">ACTIVE</Badge>}
                    </TableCell>
                    <TableCell className="text-right">
                      {!revoked && (
                        <Button size="sm" variant="outline" onClick={() => setConfirmId(t.id)}>
                          회수
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>

          <div className="flex items-center justify-between pt-2">
            <Button disabled={!data?.hasPrevious} onClick={() => setPage((p) => Math.max(0, p - 1))}>이전</Button>
            <span>{(data?.page ?? 0) + 1} / {data?.totalPages ?? 1}</span>
            <Button disabled={!data?.hasNext} onClick={() => setPage((p) => p + 1)}>다음</Button>
          </div>
        </>
      )}

      <ConfirmDialog
        open={confirmId !== null}
        title="세션 회수"
        description="이 기기의 세션을 즉시 종료합니다. 사용자는 해당 기기에서 다시 로그인해야 합니다."
        destructive
        confirmLabel="회수"
        busy={revokeOne.isPending}
        onConfirm={() => confirmId && revokeOne.mutate(confirmId)}
        onOpenChange={(o) => { if (!o) setConfirmId(null); }}
      />

      <ConfirmDialog
        open={logoutAllOpen}
        title="모든 세션 로그아웃"
        description="이 사용자의 모든 활성 세션을 종료합니다. 모든 기기에서 즉시 다시 로그인해야 합니다."
        destructive
        confirmLabel="모두 회수"
        busy={logoutAll.isPending}
        onConfirm={() => logoutAll.mutate()}
        onOpenChange={(o) => setLogoutAllOpen(o)}
      />
    </div>
  );
}
```

⚠️ `Segmented` 컴포넌트의 `options` prop 형식 확인:
Run: `grep -A3 "interface.*Props\|type.*Props" admin/src/components/Segmented.tsx | head -15`
다르면 그에 맞춰 조정 (`{ value, label }[]` 형식이 보통).

- [ ] **Step 2: typecheck + build**

Run: `cd admin && npm run typecheck && npm run build 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: 커밋**

```bash
git add admin/src/pages/tenant/user-detail/SessionsTabPanel.tsx
git commit -m "feat(admin): Sessions tab — paged refresh tokens with per-session revoke + logout-all"
```

---

### Task 19: Playwright E2E — 사용자 상세 시나리오

**Files:**
- Create: `admin/tests/admin/user-detail.spec.ts`

- [ ] **Step 1: 기존 Playwright config 확인**

Run: `cat admin/playwright.config.ts 2>/dev/null | head -30`
Expected: baseURL, testDir 확인. `tests/` 폴더에 추가해야 함.

기존 e2e 테스트 1개 확인 (로그인 패턴 참조):
Run: `ls admin/tests/admin/ 2>/dev/null && grep -l "page.goto.*login\|loginAs" admin/tests -r 2>/dev/null | head -3`

- [ ] **Step 2: E2E spec 작성**

(기존 e2e 테스트의 로그인/시드 패턴이 있다면 그것 답습. 없으면 단순한 navigation/visibility 확인 위주.)

```ts
// admin/tests/admin/user-detail.spec.ts
import { test, expect } from "@playwright/test";

// NOTE: requires server seed where at least one tenant has at least one user with both
// a credential and an active refresh token. Adjust to your e2e fixture setup.

test.describe("Admin · 사용자 상세 페이지", () => {
  test.beforeEach(async ({ page }) => {
    // Adapt to actual login flow.
    await page.goto("/login");
    await page.fill('input[name="email"]', process.env.E2E_ADMIN_EMAIL ?? "ops@local");
    await page.fill('input[name="password"]', process.env.E2E_ADMIN_PASSWORD ?? "ChangeMe1!");
    await page.click('button[type="submit"]');
    await page.waitForURL(/\/tenants/);
  });

  test("사용자 목록 → 상세 → Credentials/Sessions 탭 전환", async ({ page }) => {
    // List one tenant, click into Users tab, click first user row.
    const tenantLink = page.locator('a[href*="/tenants/"]').first();
    await tenantLink.click();
    await page.click('a[href$="/users"]');
    const firstUserRow = page.locator("table tbody tr").first();
    await firstUserRow.click();

    // Default tab = Credentials
    await expect(page.locator('[role="tab"][data-state="active"]:has-text("Credentials")')).toBeVisible();

    // Switch to Sessions
    await page.click('[role="tab"]:has-text("Sessions")');
    await expect(page).toHaveURL(/tab=sessions/);

    // 활성만 / 전체 토글 존재 확인
    await expect(page.locator('text=활성만')).toBeVisible();
  });

  test("Sessions 탭 — 모두 로그아웃 모달 표시 + 취소", async ({ page }) => {
    const tenantLink = page.locator('a[href*="/tenants/"]').first();
    await tenantLink.click();
    await page.click('a[href$="/users"]');
    await page.locator("table tbody tr").first().click();
    await page.click('[role="tab"]:has-text("Sessions")');

    await page.click('button:has-text("모두 로그아웃")');
    await expect(page.locator('text=모든 세션 로그아웃')).toBeVisible();
    await page.click('button:has-text("취소")');
    await expect(page.locator('text=모든 세션 로그아웃')).not.toBeVisible();
  });
});
```

- [ ] **Step 3: Playwright 실행 (선택, 환경에 따라 skip 가능)**

Run: `cd admin && npm run e2e 2>&1 | tail -20`
- 환경 미준비(서버 미기동, 시드 부족 등)면 통과 어려울 수 있음 — Phase 4에서 환경 정비 후 다시 시도. 일단 spec 파일만 commit.

- [ ] **Step 4: 커밋**

```bash
git add admin/tests/admin/user-detail.spec.ts
git commit -m "test(admin): e2e for user-detail page — tab switching + logout-all confirm modal"
```

---

## Phase 4: 폴리싱 & 문서 (4주차)

### Task 20: 운영자 onboarding 문서 갱신

**Files:**
- Modify: `admin/README.md` (있으면)
- Modify: `docs/architecture.md` §10 변경 이력

- [ ] **Step 1: `admin/README.md` 확인 + 사용자 상세 섹션 추가**

Run: `ls admin/README.md 2>/dev/null && head -50 admin/README.md`
- 있으면 "사용자 360° 뷰" 섹션 추가: AAGUID 라벨 의미, Sessions 탭 사용법, 개별 vs 전체 revoke 차이.
- 없으면 만들 필요 없음.

- [ ] **Step 2: `docs/architecture.md` §10 변경 이력에 1줄 추가**

```markdown
- 2026-05-24: Admin 사용자 360° 뷰 — paged credentials/refresh-tokens, AAGUID 라벨, 개별 세션 revoke (EndUserDetailView Breaking change). spec: docs/superpowers/specs/2026-05-24-admin-user-360-view-design.md
```

(파일에 §10 변경 이력 섹션이 있다고 가정. 없으면 §10 끝에 적당히 추가.)

- [ ] **Step 3: 커밋**

```bash
git add admin/README.md docs/architecture.md
git commit -m "docs: admin 사용자 360° 뷰 onboarding + 변경 이력 갱신"
```

---

### Task 21: 최종 회귀 — 전체 server check + admin build + typecheck

- [ ] **Step 1: server check**

Run: `cd server && ./gradlew check --console=plain 2>&1 | tail -10`
Expected: BUILD SUCCESSFUL

- [ ] **Step 2: admin build + typecheck + test**

Run: `cd admin && npm run typecheck && npm run build && npm run test -- --run 2>&1 | tail -15`
Expected: 모두 통과

- [ ] **Step 3: 통합 dev 환경에서 수동 verify (선택)**

Run: `cd server && ./gradlew bootRun --args='--spring.profiles.active=local' &`
별도 터미널: `cd admin && npm run dev`
브라우저: `http://localhost:5173` 로그인 → 테넌트 → Users 탭 → 사용자 클릭 → Credentials/Sessions 탭 동작 확인.
이상 없으면 종료.

- [ ] **Step 4: PR 준비 + push**

```bash
git log --oneline main..HEAD
# 17~20개 커밋 보임
git push -u origin worktree-admin-user-360-view
```

이후 GitHub에서 PR 작성. PR body는 spec/plan 링크 포함:

```
## Summary
- 5개 admin endpoint (기존 2개 / 변경 1개 / 신규 2개) + DELETE 1개
- AaguidLabelResolver — MDS BLOB 기반 AAGUID 라벨 변환 + 캐시
- 클라이언트 사용자 상세 페이지 탭 구조 + Credentials 탭 액션 + Sessions 탭
- EndUserDetailView BREAKING: credentials 필드가 List → Counts 객체

Spec: docs/superpowers/specs/2026-05-24-admin-user-360-view-design.md
Plan: docs/superpowers/plans/2026-05-24-admin-user-360-view.md

## Test plan
- [ ] server ./gradlew check 통과
- [ ] admin npm run typecheck / build / test 통과
- [ ] 통합 dev 환경에서 수동 verify (Credentials revoke / Sessions revoke / logout-all / 탭 전환)
```

---

## 실행 노트 — 슬라이스 테스트와 admin DS 격리

`RefreshTokenSeed` / `CredentialSeed`가 `adminJdbcTemplate`(VPD-exempt, APP_ADMIN) DS를 사용하는 경우, 슬라이스 테스트의 `@Transactional` 어노테이션이 메인 DS만 롤백하므로 admin DS 시드 데이터는 commit되어 누적될 수 있다. 기존 `RefreshTokenAdminWriterSliceTest` / `CredentialAdminWriterSliceTest`가 동일 패턴인지 확인하고 (확인 결과 그러함 — 각 테스트가 unique한 tenant id를 새로 만들어 충돌 회피), 신규 슬라이스 테스트도 같은 패턴 따른다: `seed.createTenant("prefix-" + UUID.randomUUID())`로 tenant 단위 격리.

`CredentialSeed`는 production `Credential` 생성 메서드를 활용해 메인 DS에 insert해야 한다 (VPD 컨텍스트 설정 후). admin DS로 insert하면 RP가 그 credential을 보지 못해 일관성 깨짐.

## Self-Review Summary

이 plan을 작성 후 다음을 확인했다:

**Spec coverage**: spec §4 endpoints(5/5) / §5 UI(목록·상세·탭·액션) / §6 도메인(`AaguidLabelResolver`, paged repos, `REFRESH_TOKEN_REVOKED` audit) / §7 test 전략(unit/slice/integration/E2E) / §8 phase / §9 위험 / §10 open questions(전부 plan에 박힌 결정) 모두 매핑됨.

**Placeholder scan**: 모든 step에 실제 코드 / 명령어 / expected output 포함. ⚠️ 표기는 "production code 시그니처에 따라 살짝 조정" 노트(필요한 정확성을 잃지 않고 실 작업자의 적응 유도).

**Type consistency**: 서버 record `AaguidLabel(aaguid, displayName, fromMds)` ↔ TS `AaguidLabelDto(aaguid, displayName, fromMds)` ↔ 컴포넌트 prop `aaguid: AaguidLabelDto` 일관. `EndUserDetailView`의 `credentials` 필드 변경이 server/client에서 같은 형식(`{ active, suspended, revoked }`)으로 잡힘.

**의도된 의존성 순서**: Task 1(audit enum) → 2-3(resolver) → 4-7(repo) → 8-9(detail/paged) → 10-11(delete controller) → 12(integration) → 13-17(client phase 2) → 18-19(phase 3) → 20-21(phase 4). 각 단계가 이전 task에 의존하므로 순서 준수 필수.
