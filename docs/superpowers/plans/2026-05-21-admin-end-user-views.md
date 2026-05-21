# Admin End-user Views Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only "Users" tab to the Admin console's tenant detail page — list/search end-users (`tenant_user`) and view a single user's passkeys and last activity.

**Architecture:** A new `AdminEndUserController` exposes two GET endpoints under `/api/v1/admin/tenants/{tenantId}/users` (coexisting with the existing `AdminUserSessionController` on the same base path — different HTTP methods, no routing conflict). The list endpoint uses a paged JPQL query with a `LEFT JOIN` aggregate to count active passkeys per user without N+1. The frontend adds a `UsersTab` (list) and a separate-route `UserDetailPage` (detail), wired into the existing tenant tab bar and router.

**Tech Stack:** Spring Boot 3.5 / Java 17 (Gradle, JPA, Oracle VPD), React 18 + TypeScript + Vite + TanStack Query (admin SPA).

---

## File Structure

**Backend (worktree root: `/Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views`)**

- Create `server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java` — the two GET endpoints + `EndUserView`/`EndUserDetailView` inner records.
- Modify `server/src/main/java/com/crosscert/passkey/tenant/repository/TenantUserRepository.java` — add `EndUserRow` projection + `findByTenantIdWithSearch` paged query.
- Modify `server/src/main/java/com/crosscert/passkey/audit/service/AuditAggregationService.java` — add `lastEventForSubject`.
- Create `server/src/test/java/com/crosscert/passkey/slice/admin/AdminEndUserControllerSliceTest.java` — `@WebMvcTest` slice, mocks all repos.
- Create `server/src/test/java/com/crosscert/passkey/integration/admin/AdminEndUserIntegrationTest.java` — real-Oracle search/aggregation/isolation checks.

**Frontend**

- Modify `admin/src/types/api.ts` — add `EndUserView`, `EndUserDetailView` interfaces.
- Create `admin/src/pages/tenant/UsersTab.tsx` — list view (search + pagination).
- Create `admin/src/pages/tenant/UserDetailPage.tsx` — detail view (meta card + passkey table).
- Modify `admin/src/pages/TenantDetailPage.tsx` — add "Users" tab to `TABS`.
- Modify `admin/src/App.tsx` — lazy-load + route the two new pages.

**Docs**

- Modify `docs/architecture.md` — append a §11 changelog row.

---

## Task 1: Backend — `EndUserRow` projection + repository query

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/tenant/repository/TenantUserRepository.java`

The current repository has only `findByExternalId` and `countByTenantId`. Add a Spring Data projection interface and a paged search query that also counts each user's ACTIVE passkeys via a `LEFT JOIN` (avoids per-row N+1 counts).

- [ ] **Step 1: Read the current file**

Run: `cat server/src/main/java/com/crosscert/passkey/tenant/repository/TenantUserRepository.java`
Note its existing imports and the `TenantUser` / `UUID` usage.

- [ ] **Step 2: Add the projection interface and query method**

Add these imports if missing: `org.springframework.data.domain.Page`, `org.springframework.data.domain.Pageable`, `org.springframework.data.jpa.repository.Query`, `org.springframework.data.repository.query.Param`, `java.time.OffsetDateTime`.

Add inside the `TenantUserRepository` interface body:

```java
  /**
   * Row projection for the admin end-user list. {@code activeCredentialCount} comes from a
   * LEFT JOIN aggregate so the list endpoint avoids an N+1 count-per-row.
   */
  interface EndUserRow {
    UUID getId();

    String getExternalId();

    String getDisplayName();

    long getActiveCredentialCount();

    OffsetDateTime getCreatedAt();

    OffsetDateTime getUpdatedAt();
  }

  /**
   * Paged end-user listing with an optional case-insensitive substring filter over externalId and
   * displayName. {@code countQuery} is given explicitly because the main query's GROUP BY would
   * otherwise make Spring Data derive a wrong count. Passing {@code null}/blank {@code q} returns
   * the full tenant page.
   */
  @Query(
      value =
          "SELECT u.id AS id, u.externalId AS externalId, u.displayName AS displayName, "
              + "u.createdAt AS createdAt, u.updatedAt AS updatedAt, "
              + "COUNT(c.id) AS activeCredentialCount "
              + "FROM TenantUser u "
              + "LEFT JOIN com.crosscert.passkey.credential.domain.Credential c "
              + "  ON c.tenantUserId = u.id "
              + "  AND c.status = com.crosscert.passkey.credential.domain.CredentialStatus.ACTIVE "
              + "WHERE u.tenantId = :tenantId "
              + "  AND (:q IS NULL "
              + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
              + "       OR LOWER(COALESCE(u.displayName, '')) LIKE LOWER(CONCAT('%', :q, '%'))) "
              + "GROUP BY u.id, u.externalId, u.displayName, u.createdAt, u.updatedAt",
      countQuery =
          "SELECT COUNT(u) FROM TenantUser u "
              + "WHERE u.tenantId = :tenantId "
              + "  AND (:q IS NULL "
              + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
              + "       OR LOWER(COALESCE(u.displayName, '')) LIKE LOWER(CONCAT('%', :q, '%')))")
  Page<EndUserRow> findByTenantIdWithSearch(
      @Param("tenantId") UUID tenantId, @Param("q") String q, Pageable pageable);
```

- [ ] **Step 3: Verify it compiles**

Run: `cd server && ./gradlew compileJava`
Expected: `BUILD SUCCESSFUL`. (Query correctness is verified by the integration test in Task 6 — compilation here only confirms JPQL/projection syntax is well-formed at the Java level.)

- [ ] **Step 4: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add server/src/main/java/com/crosscert/passkey/tenant/repository/TenantUserRepository.java
git commit -m "$(cat <<'EOF'
tenant: add paged end-user search query with active-passkey count

EndUserRow projection + findByTenantIdWithSearch — LEFT JOIN aggregate
counts ACTIVE credentials per user in one query (no N+1). Explicit
countQuery because the GROUP BY would break Spring Data's count derivation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Backend — `AuditAggregationService.lastEventForSubject`

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/audit/service/AuditAggregationService.java`

The end-user detail view shows "last activity" — the most recent audit event whose `subject_id` is this user's id. Clone the existing `lastEventAt(tenantId)` and add a `subject_id` filter.

- [ ] **Step 1: Read the current `lastEventAt` method**

Run: `grep -n "lastEventAt" -A18 server/src/main/java/com/crosscert/passkey/audit/service/AuditAggregationService.java`
It runs `SELECT MAX(created_at) FROM audit_log WHERE tenant_id = :tid` and handles `OffsetDateTime` / `java.sql.Timestamp` / null results.

- [ ] **Step 2: Add `lastEventForSubject`**

Add this method right after `lastEventAt` in the class (same `@Transactional(readOnly = true)` annotation that `lastEventAt` carries — match the existing method's annotations exactly):

```java
  /**
   * Most recent audit event timestamp for a single subject (e.g. one tenant user). audit_log links
   * the subject loosely via {@code subject_id}; the caller already holds the tenant context, so the
   * tenant_id predicate keeps VPD semantics consistent with {@link #lastEventAt}.
   */
  @Transactional(readOnly = true)
  public Optional<OffsetDateTime> lastEventForSubject(UUID tenantId, String subjectId) {
    Object raw =
        em.createNativeQuery(
                "SELECT MAX(created_at) FROM audit_log "
                    + "WHERE tenant_id = :tid AND subject_id = :sid")
            .setParameter("tid", tenantId)
            .setParameter("sid", subjectId)
            .getSingleResult();
    if (raw == null) {
      return Optional.empty();
    }
    if (raw instanceof OffsetDateTime odt) {
      return Optional.of(odt);
    }
    if (raw instanceof java.sql.Timestamp ts) {
      return Optional.of(ts.toInstant().atOffset(ZoneOffset.UTC));
    }
    return Optional.empty();
  }
```

- [ ] **Step 3: Verify it compiles**

Run: `cd server && ./gradlew compileJava`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 4: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add server/src/main/java/com/crosscert/passkey/audit/service/AuditAggregationService.java
git commit -m "$(cat <<'EOF'
audit: add lastEventForSubject for per-user last-activity lookup

Mirrors lastEventAt with an extra subject_id predicate so the admin
end-user detail view can show a user's most recent audit timestamp.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Backend — failing slice test for `AdminEndUserController`

**Files:**
- Create: `server/src/test/java/com/crosscert/passkey/slice/admin/AdminEndUserControllerSliceTest.java`

Write the test FIRST. It references `AdminEndUserController` which does not exist yet — so it will fail to compile. That compile failure is the expected RED.

This test mirrors `AdminUserSessionControllerSliceTest` (same `@WebMvcTest` harness, same `loginAs` helper, same `excludeAutoConfiguration` + `@Import`).

- [ ] **Step 1: Write the test file**

```java
package com.crosscert.passkey.slice.admin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.controller.AdminEndUserController;
import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.audit.service.AuditAggregationService;
import com.crosscert.passkey.common.exception.GlobalExceptionHandler;
import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository.EndUserRow;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies the end-user list/detail endpoints enforce tenant access and shape the response
 * envelope. Repositories are mocked — query correctness is covered by the integration test.
 */
@WebMvcTest(
    controllers = AdminEndUserController.class,
    excludeAutoConfiguration = {
      org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
      org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
    })
@Import({GlobalExceptionHandler.class, TraceIdFilter.class})
class AdminEndUserControllerSliceTest {

  @Autowired MockMvc mvc;
  @MockBean TenantUserRepository tenantUserRepo;
  @MockBean CredentialRepository credentialRepo;
  @MockBean AuditAggregationService auditAgg;

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void list_returns_paged_users() throws Exception {
    UUID tenantId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    EndUserRow row = endUserRow(UUID.randomUUID(), "ext-1", "Alice", 2);
    Page<EndUserRow> page = new PageImpl<>(List.of(row), Pageable.ofSize(50), 1);
    when(tenantUserRepo.findByTenantIdWithSearch(eq(tenantId), isNull(), any(Pageable.class)))
        .thenReturn(page);

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users", tenantId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.content[0].externalId").value("ext-1"))
        .andExpect(jsonPath("$.data.content[0].displayName").value("Alice"))
        .andExpect(jsonPath("$.data.content[0].activeCredentialCount").value(2))
        .andExpect(jsonPath("$.data.totalElements").value(1));
  }

  @Test
  void list_passes_search_q_to_repo() throws Exception {
    UUID tenantId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);
    when(tenantUserRepo.findByTenantIdWithSearch(eq(tenantId), eq("alice"), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(), Pageable.ofSize(50), 0));

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users", tenantId).param("q", "alice"))
        .andExpect(status().isOk());

    verify(tenantUserRepo).findByTenantIdWithSearch(eq(tenantId), eq("alice"), any(Pageable.class));
  }

  @Test
  void detail_returns_user_with_credentials() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-9", "Carol");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));
    when(credentialRepo.findAllByTenantUserId(tenantUserId)).thenReturn(List.of());
    when(auditAgg.lastEventForSubject(tenantId, tenantUserId.toString()))
        .thenReturn(Optional.of(OffsetDateTime.now(ZoneOffset.UTC)));

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users/{userId}", tenantId, tenantUserId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.externalId").value("ext-9"))
        .andExpect(jsonPath("$.data.credentials").isArray())
        .andExpect(jsonPath("$.data.lastActivityAt").exists());
  }

  @Test
  void detail_rejects_cross_tenant_user() throws Exception {
    UUID pathTenantId = UUID.randomUUID();
    UUID otherTenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(otherTenantId, "ext-x", "Mallory");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users/{userId}", pathTenantId, tenantUserId))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("C001"));

    verify(credentialRepo, never()).findAllByTenantUserId(any());
  }

  @Test
  void detail_returns_404_when_user_missing() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.empty());

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users/{userId}", tenantId, tenantUserId))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("C003"));
  }

  @Test
  void list_rejected_when_rp_admin_targets_other_tenant() throws Exception {
    UUID pathTenantId = UUID.randomUUID();
    UUID rpAdminTenantId = UUID.randomUUID();
    loginAs(AdminRole.RP_ADMIN, rpAdminTenantId);

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users", pathTenantId))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));

    verify(tenantUserRepo, never())
        .findByTenantIdWithSearch(any(), any(), any(Pageable.class));
  }

  private static EndUserRow endUserRow(
      UUID id, String externalId, String displayName, long activeCredentialCount) {
    return new EndUserRow() {
      @Override
      public UUID getId() {
        return id;
      }

      @Override
      public String getExternalId() {
        return externalId;
      }

      @Override
      public String getDisplayName() {
        return displayName;
      }

      @Override
      public long getActiveCredentialCount() {
        return activeCredentialCount;
      }

      @Override
      public OffsetDateTime getCreatedAt() {
        return OffsetDateTime.now(ZoneOffset.UTC);
      }

      @Override
      public OffsetDateTime getUpdatedAt() {
        return OffsetDateTime.now(ZoneOffset.UTC);
      }
    };
  }

  private static void loginAs(AdminRole role, UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, role, "ops@local", "Ops");
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities()));
  }
}
```

- [ ] **Step 2: Run the test to confirm it fails (RED)**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.AdminEndUserControllerSliceTest"`
Expected: **compilation failure** — `cannot find symbol: class AdminEndUserController`. This is the expected RED state (feature missing).

- [ ] **Step 3: Commit the failing test**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add server/src/test/java/com/crosscert/passkey/slice/admin/AdminEndUserControllerSliceTest.java
git commit -m "$(cat <<'EOF'
test: failing slice test for AdminEndUserController (RED)

Six cases: paged list, search q passthrough, detail with credentials,
cross-tenant rejection (C001), 404 (C003), RP_ADMIN forbidden (M002).
Fails to compile until the controller exists.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Backend — implement `AdminEndUserController` (GREEN)

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java`

Implement the controller so the Task 3 slice test passes. `CredentialView` (`com.crosscert.passkey.credential.api.CredentialView`) is reused for the detail's passkey list — `AdminCredentialController` already reuses it, so this is an established pattern, not new duplication.

- [ ] **Step 1: Write the controller**

```java
package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.service.AuditAggregationService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository.EndUserRow;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only end-user (tenant_user) listing and detail. Shares the
 * {@code /api/v1/admin/tenants/{tenantId}/users} base path with {@code AdminUserSessionController}
 * (force-logout) — no conflict, the methods/sub-paths differ. Both PLATFORM_OPERATOR and the
 * tenant's own RP_ADMIN may read, enforced by {@link AdminAuthz#requireTenantAccess}.
 */
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/users")
@RequiredArgsConstructor
@Tag(name = "Admin · End Users", description = "Per-tenant end-user listing and detail (read-only).")
public class AdminEndUserController {

  private final TenantUserRepository tenantUserRepo;
  private final CredentialRepository credentialRepo;
  private final AuditAggregationService auditAgg;

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
          r.getId(),
          r.getExternalId(),
          r.getDisplayName(),
          r.getActiveCredentialCount(),
          r.getCreatedAt(),
          r.getUpdatedAt());
    }
  }

  /** Full detail for one end-user: metadata, last activity, and the user's passkeys. */
  public record EndUserDetailView(
      UUID id,
      String externalId,
      String displayName,
      OffsetDateTime createdAt,
      OffsetDateTime updatedAt,
      long activeCredentialCount,
      OffsetDateTime lastActivityAt,
      List<CredentialView> credentials) {}

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(
      summary = "List end-users",
      description = "Paginated. Optional q filters externalId / displayName (case-insensitive).")
  public ApiResponse<PageResponse<EndUserView>> list(
      @PathVariable UUID tenantId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size,
      @RequestParam(required = false) String q) {
    AdminAuthz.requireTenantAccess(tenantId);
    Pageable pageable = PageRequest.of(page, size);
    String trimmed = (q == null || q.isBlank()) ? null : q.trim();
    return ApiResponse.ok(
        PageResponse.from(
            tenantUserRepo
                .findByTenantIdWithSearch(tenantId, trimmed, pageable)
                .map(EndUserView::from)));
  }

  @GetMapping("/{tenantUserId}")
  @Transactional(readOnly = true)
  @Operation(summary = "Get one end-user with passkeys and last-activity")
  public ApiResponse<EndUserDetailView> detail(
      @PathVariable UUID tenantId, @PathVariable UUID tenantUserId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantUser user =
        tenantUserRepo
            .findById(tenantUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    if (!user.getTenantId().equals(tenantId)) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "tenantUserId does not belong to the path tenant");
    }
    List<CredentialView> credentials =
        credentialRepo.findAllByTenantUserId(tenantUserId).stream()
            .map(CredentialView::from)
            .toList();
    long activeCount =
        credentials.stream().filter(c -> "ACTIVE".equals(c.status())).count();
    OffsetDateTime lastActivity =
        auditAgg.lastEventForSubject(tenantId, tenantUserId.toString()).orElse(null);
    return ApiResponse.ok(
        new EndUserDetailView(
            user.getId(),
            user.getExternalId(),
            user.getDisplayName(),
            user.getCreatedAt(),
            user.getUpdatedAt(),
            activeCount,
            lastActivity,
            credentials));
  }
}
```

- [ ] **Step 2: Verify the `PageResponse.from` signature**

Run: `grep -n "static.*from\|record PageResponse\|class PageResponse" server/src/main/java/com/crosscert/passkey/common/response/PageResponse.java`
Confirm `PageResponse.from(Page<T>)` exists and accepts a Spring `Page`. `AdminTenantController.list` already returns `ApiResponse<PageResponse<TenantView>>` from a `Page`, so this helper exists — if the method name differs, match what `AdminTenantController` uses.

- [ ] **Step 3: Run the slice test to confirm GREEN**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.admin.AdminEndUserControllerSliceTest"`
Expected: `BUILD SUCCESSFUL`, all 6 tests pass.

- [ ] **Step 4: Run ArchUnit to confirm no rule violation**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.architecture.*"`
Expected: `BUILD SUCCESSFUL`. (New controller: `@RequestMapping` starts with `/api/v1/admin` — Rule 5 OK; calls `AdminAuthz` — Rule 6 OK; admin controllers may call repositories directly — Rule 3 exempt.)

- [ ] **Step 5: Format and commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views/server
./gradlew spotlessApply
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add server/src/main/java/com/crosscert/passkey/admin/controller/AdminEndUserController.java
git commit -m "$(cat <<'EOF'
admin: add read-only end-user list/detail endpoints

GET /api/v1/admin/tenants/{tenantId}/users — paged, searchable list.
GET .../users/{tenantUserId} — detail with passkey list + last activity.
Tenant-scoped via requireTenantAccess; coexists with the force-logout
controller on the same base path (different methods).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Backend — integration test for search/aggregation/isolation

**Files:**
- Create: `server/src/test/java/com/crosscert/passkey/integration/admin/AdminEndUserIntegrationTest.java`

The slice test mocks repositories, so the JPQL query in Task 1 is unverified. This integration test runs against the real docker-compose Oracle: it seeds two tenants with users and credentials, then asserts the repository query is correct.

- [ ] **Step 1: Inspect the integration test base + seeding helpers**

Run: `cat server/src/test/java/com/crosscert/passkey/integration/support/IntegrationTestBase.java`
Run: `cat server/src/test/java/com/crosscert/passkey/integration/support/TenantSeed.java`
Run: `ls server/src/test/java/com/crosscert/passkey/integration/tenant/isolation/`

`IntegrationTestBase` connects to the docker Oracle and runs Flyway; `TenantSeed` (a bean from `TestSupportConfig`) has `createTenant(slug)` and `createUser(tenantId, externalId)` and a `withTenant(tenantId, Runnable/Supplier)` helper. Read `TenantIsolationIntegrationTest` and `RawSqlBypassTest` for how existing tests seed credential rows under a tenant context (credential is a VPD tenant-scoped table — inserts need the tenant context set, which `TenantSeed.withTenant` provides).

- [ ] **Step 2: Write the integration test**

Extend `IntegrationTestBase`. Autowire `TenantUserRepository` and `TenantSeed` (and whatever the existing tests use to insert credentials — likely `CredentialRepository` under `withTenant`, or a raw-SQL helper; follow `TenantIsolationIntegrationTest`'s exact approach). The test seeds:
- Tenant A: 2 users — user A1 with 2 ACTIVE credentials, user A2 with 1 ACTIVE + 1 REVOKED.
- Tenant B: 1 user — user B1 with 1 ACTIVE credential, displayName `"Zoe"`.

Then assert (each its own `@Test` method):

```java
package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository.EndUserRow;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

/**
 * Exercises {@link TenantUserRepository#findByTenantIdWithSearch} against the real Oracle schema —
 * the active-passkey aggregate, the externalId/displayName search, paging, and tenant isolation.
 */
class AdminEndUserIntegrationTest extends IntegrationTestBase {

  @Autowired TenantUserRepository tenantUserRepo;
  // Autowire the same seeding collaborators TenantIsolationIntegrationTest uses
  // (TenantSeed for tenants/users; the credential-insert path it demonstrates).

  @Test
  void list_counts_only_active_credentials_per_user() {
    // Arrange: seed tenant A with user A1 (2 ACTIVE creds) and user A2 (1 ACTIVE + 1 REVOKED).
    // Act:
    Page<EndUserRow> page =
        tenantUserRepo.findByTenantIdWithSearch(tenantAId, null, PageRequest.of(0, 50));
    // Assert: A1.activeCredentialCount == 2, A2.activeCredentialCount == 1 (REVOKED excluded).
    assertThat(page.getContent())
        .extracting(EndUserRow::getExternalId, EndUserRow::getActiveCredentialCount)
        .contains(
            org.assertj.core.groups.Tuple.tuple("a1", 2L),
            org.assertj.core.groups.Tuple.tuple("a2", 1L));
  }

  @Test
  void search_matches_external_id_and_display_name() {
    // q matching A1's externalId returns A1; q matching B1's displayName "Zoe" returns B1.
    Page<EndUserRow> byExternalId =
        tenantUserRepo.findByTenantIdWithSearch(tenantAId, "a1", PageRequest.of(0, 50));
    assertThat(byExternalId.getContent()).extracting(EndUserRow::getExternalId).containsExactly("a1");

    Page<EndUserRow> byDisplayName =
        tenantUserRepo.findByTenantIdWithSearch(tenantBId, "zoe", PageRequest.of(0, 50));
    assertThat(byDisplayName.getContent()).extracting(EndUserRow::getExternalId).containsExactly("b1");
  }

  @Test
  void list_is_tenant_isolated() {
    // Tenant A's listing must not contain tenant B's user.
    Page<EndUserRow> page =
        tenantUserRepo.findByTenantIdWithSearch(tenantAId, null, PageRequest.of(0, 50));
    assertThat(page.getContent()).extracting(EndUserRow::getExternalId).doesNotContain("b1");
  }

  @Test
  void count_query_matches_filtered_total() {
    // With a q that matches exactly one user, totalElements must be 1 (GROUP BY count correctness).
    Page<EndUserRow> page =
        tenantUserRepo.findByTenantIdWithSearch(tenantAId, "a1", PageRequest.of(0, 50));
    assertThat(page.getTotalElements()).isEqualTo(1);
  }
}
```

Replace the `// Arrange` comments and `tenantAId` / `tenantBId` fields with real seeding in a `@BeforeEach` (or per-test), using `TenantSeed` and the credential-insert pattern from `TenantIsolationIntegrationTest`. Capture the seeded tenant ids into fields. Do NOT leave the arrange steps as comments in the final code — they must be real, executable seeding.

- [ ] **Step 3: Run the integration test**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.integration.admin.AdminEndUserIntegrationTest"`
Expected: `BUILD SUCCESSFUL`, 4 tests pass.
If the docker Oracle is not running, start it first: `cd server && docker compose up -d` and wait for healthy.

- [ ] **Step 4: Format and commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views/server
./gradlew spotlessApply
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add server/src/test/java/com/crosscert/passkey/integration/admin/AdminEndUserIntegrationTest.java
git commit -m "$(cat <<'EOF'
test: integration test for end-user search query

Seeds two tenants and asserts findByTenantIdWithSearch: active-passkey
count excludes REVOKED, search matches externalId and displayName,
tenant isolation holds, and the GROUP BY countQuery is correct.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Frontend — `EndUserView` / `EndUserDetailView` types

**Files:**
- Modify: `admin/src/types/api.ts`

- [ ] **Step 1: Find where to place the new types**

Run: `grep -n "OverviewStatsView\|CredentialView\|PageResponse" admin/src/types/api.ts`
Place the new interfaces near the other tenant-scoped view types, following the file's existing comment style.

- [ ] **Step 2: Add the interfaces**

Add to `admin/src/types/api.ts`:

```ts
// ─── End Users (tenant_user) ───

export interface EndUserView {
  id: string;
  externalId: string;
  displayName: string | null;
  activeCredentialCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface EndUserDetailView {
  id: string;
  externalId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
  activeCredentialCount: number;
  lastActivityAt: string | null;
  credentials: CredentialView[];
}
```

- [ ] **Step 3: Verify typecheck**

Run: `cd admin && npm run typecheck`
Expected: clean (`tsc --noEmit` exits 0).

- [ ] **Step 4: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add admin/src/types/api.ts
git commit -m "$(cat <<'EOF'
admin: add EndUserView / EndUserDetailView types

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Frontend — `UsersTab` list view

**Files:**
- Create: `admin/src/pages/tenant/UsersTab.tsx`

A read-only list: search box (debounced) + paginated table. Modeled on `CredentialsTab.tsx` but stripped of all mutations/dialogs. Row click navigates to the detail route.

- [ ] **Step 1: Write `UsersTab.tsx`**

```tsx
import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { apiGet } from "@/lib/api";
import { formatCount, formatDateTime } from "@/lib/format";
import type { EndUserView, PageResponse } from "@/types/api";

/** Debounce a fast-changing value (e.g. a search box) — local copy of the CredentialsTab helper. */
function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

export function UsersTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const [page, setPage] = React.useState(0);
  const size = 50;
  const [search, setSearch] = React.useState("");
  const debouncedSearch = useDebounced(search, 300);

  // Reset to the first page whenever the search term changes.
  React.useEffect(() => {
    setPage(0);
  }, [debouncedSearch]);

  const { data, isLoading } = useQuery({
    queryKey: ["endUsers", tenantId, { page, size, q: debouncedSearch }],
    queryFn: () => {
      const q = debouncedSearch.trim();
      const qParam = q.length === 0 ? "" : `&q=${encodeURIComponent(q)}`;
      return apiGet<PageResponse<EndUserView>>(
        `/api/v1/admin/tenants/${tenantId}/users?page=${page}&size=${size}${qParam}`,
      );
    },
    enabled: !!tenantId,
  });

  const users = data?.content ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Users"
        description="이 tenant의 end-user(tenant_user) 목록. externalId 또는 표시 이름으로 검색."
      />

      <div className="relative max-w-sm">
        <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
        <Input
          className="pl-8"
          placeholder="externalId / 표시 이름 검색"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">불러오는 중…</p>
      ) : users.length === 0 ? (
        <EmptyState title="조건에 맞는 사용자가 없습니다." />
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            {formatCount(data?.totalElements ?? users.length)}명
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>External ID</TableHead>
                <TableHead>표시 이름</TableHead>
                <TableHead>활성 Passkey</TableHead>
                <TableHead>생성</TableHead>
                <TableHead>수정</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => (
                <TableRow
                  key={u.id}
                  className="cursor-pointer"
                  onClick={() => navigate(`/tenants/${tenantId}/users/${u.id}`)}
                >
                  <TableCell className="font-mono text-xs">{u.externalId}</TableCell>
                  <TableCell>{u.displayName ?? "—"}</TableCell>
                  <TableCell>{formatCount(u.activeCredentialCount)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(u.createdAt)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(u.updatedAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          <div className="flex items-center justify-between pt-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!data?.hasPrevious}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              이전
            </Button>
            <span className="text-xs text-muted-foreground">
              {(data?.page ?? 0) + 1} / {data?.totalPages ?? 1}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={!data?.hasNext}
              onClick={() => setPage((p) => p + 1)}
            >
              다음
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify typecheck**

Run: `cd admin && npm run typecheck`
Expected: clean. (If `EmptyState`/`PageHeader`/`Button`/`Table` prop names differ from this code, open `admin/src/pages/tenant/CredentialsTab.tsx` and copy the exact prop usage — those components are already used there.)

- [ ] **Step 3: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add admin/src/pages/tenant/UsersTab.tsx
git commit -m "$(cat <<'EOF'
admin: add UsersTab — paginated, searchable end-user list

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Frontend — `UserDetailPage` detail view

**Files:**
- Create: `admin/src/pages/tenant/UserDetailPage.tsx`

A separate-route detail page: metadata card + the user's passkey table. Read-only, no mutations.

- [ ] **Step 1: Write `UserDetailPage.tsx`**

```tsx
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { apiGet } from "@/lib/api";
import { formatCount, formatDateTime, lastN } from "@/lib/format";
import type { EndUserDetailView } from "@/types/api";

export function UserDetailPage() {
  const { tenantId, tenantUserId } = useParams<{
    tenantId: string;
    tenantUserId: string;
  }>();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["endUser", tenantId, tenantUserId],
    queryFn: () =>
      apiGet<EndUserDetailView>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }
  if (isError || !data) {
    return <EmptyState title="사용자를 찾을 수 없습니다." />;
  }

  return (
    <div className="space-y-5">
      <Link
        to={`/tenants/${tenantId}/users`}
        className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="h-3.5 w-3.5" /> 사용자 목록
      </Link>

      <PageHeader
        title={data.displayName ?? data.externalId}
        description={`External ID: ${data.externalId}`}
      />

      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Meta label="내부 ID" value={lastN(data.id, 8)} mono />
        <Meta label="활성 Passkey" value={formatCount(data.activeCredentialCount)} />
        <Meta label="생성" value={formatDateTime(data.createdAt)} />
        <Meta
          label="최근 활동"
          value={data.lastActivityAt ? formatDateTime(data.lastActivityAt) : "—"}
        />
      </div>

      <div className="space-y-2">
        <h2 className="text-sm font-semibold">Passkeys</h2>
        {data.credentials.length === 0 ? (
          <EmptyState title="등록된 passkey가 없습니다." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Credential ID</TableHead>
                <TableHead>닉네임</TableHead>
                <TableHead>상태</TableHead>
                <TableHead>마지막 사용</TableHead>
                <TableHead>생성</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.credentials.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-xs">{lastN(c.credentialId, 12)}</TableCell>
                  <TableCell>{c.nickname ?? "—"}</TableCell>
                  <TableCell>
                    <Badge variant={c.status === "ACTIVE" ? "success" : "destructive"}>
                      {c.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {c.lastUsedAt ? formatDateTime(c.lastUsedAt) : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(c.createdAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}

function Meta({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={mono ? "mt-0.5 font-mono text-sm" : "mt-0.5 text-sm"}>{value}</div>
    </div>
  );
}
```

- [ ] **Step 2: Verify typecheck**

Run: `cd admin && npm run typecheck`
Expected: clean. (`React` is referenced in the `Meta` prop type — if the project's tsconfig needs an explicit `import * as React from "react"`, add it; check whether `CredentialsTab.tsx` imports React explicitly and match.)

- [ ] **Step 3: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add admin/src/pages/tenant/UserDetailPage.tsx
git commit -m "$(cat <<'EOF'
admin: add UserDetailPage — end-user detail with passkey list

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Frontend — wire the tab and routes

**Files:**
- Modify: `admin/src/pages/TenantDetailPage.tsx`
- Modify: `admin/src/App.tsx`

- [ ] **Step 1: Add the "Users" tab**

In `admin/src/pages/TenantDetailPage.tsx`, change the `TABS` array — insert `users` right after `api-keys` (so the order reads users → credentials → audit):

```tsx
const TABS = [
  { to: "overview", label: "개요" },
  { to: "webauthn-config", label: "WebAuthn" },
  { to: "attestation-policy", label: "AAGUID 정책" },
  { to: "api-keys", label: "API Keys" },
  { to: "users", label: "Users" },
  { to: "credentials", label: "Credentials" },
  { to: "audit-logs", label: "Audit Logs" },
  { to: "funnel", label: "Funnel" },
];
```

- [ ] **Step 2: Add lazy imports in `App.tsx`**

In `admin/src/App.tsx`, alongside the other `tenant/` lazy imports (near `CredentialsTab`), add:

```tsx
const UsersTab = lazy(() =>
  import("@/pages/tenant/UsersTab").then((m) => ({ default: m.UsersTab })),
);
const UserDetailPage = lazy(() =>
  import("@/pages/tenant/UserDetailPage").then((m) => ({ default: m.UserDetailPage })),
);
```

- [ ] **Step 3: Add the routes**

In `admin/src/App.tsx`, inside the `<Route element={<RequireTenantAccess />}>` block under `/tenants/:tenantId` (where `credentials`, `audit-logs` etc. are routed), add two routes:

```tsx
                <Route path="users" element={<UsersTab />} />
                <Route path="users/:tenantUserId" element={<UserDetailPage />} />
```

The detail route renders inside `TenantDetailPage`'s `<Outlet />`, so the tab bar stays visible. `TenantDetailPage`'s tab `NavLink` has no `end` prop, so it prefix-matches — the "Users" tab stays active on `users/:id` too. No extra work needed.

- [ ] **Step 4: Verify typecheck + build**

Run: `cd admin && npm run typecheck && npm run build`
Expected: typecheck clean, build succeeds.

- [ ] **Step 5: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add admin/src/pages/TenantDetailPage.tsx admin/src/App.tsx
git commit -m "$(cat <<'EOF'
admin: wire Users tab and end-user routes

Adds the "Users" tab to the tenant detail tab bar and routes
users (list) + users/:tenantUserId (detail) under RequireTenantAccess.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Docs — architecture changelog

**Files:**
- Modify: `docs/architecture.md`

- [ ] **Step 1: Find the changelog table**

Run: `grep -n "변경 이력" docs/architecture.md`
The §11 "변경 이력" table is at the end of the file. Read the last row to match the format.

- [ ] **Step 2: Append a new row**

Add this row at the end of the §11 changelog table (after the last existing row):

```
| 2026-05-21 | Admin End-user 조회 | Admin 콘솔 tenant 상세에 "Users" 탭 추가 — end-user(`tenant_user`) 목록·검색·상세를 조회 전용으로 제공. 신규 `AdminEndUserController` (`GET /api/v1/admin/tenants/{tenantId}/users` 목록, `.../users/{tenantUserId}` 상세) — `AdminUserSessionController`의 logout-all과 같은 base path를 메서드 차이로 공존. `TenantUserRepository.findByTenantIdWithSearch` — `Credential` LEFT JOIN 집계로 활성 passkey 개수를 N+1 없이 계산(GROUP BY라 `countQuery` 명시). `AuditAggregationService.lastEventForSubject`로 상세의 최근 활동 시각. 프론트: `UsersTab`(목록), `UserDetailPage`(별도 라우트 상세). 권한 `requireTenantAccess` — PLATFORM_OPERATOR + 자기 tenant RP_ADMIN. 테스트: `AdminEndUserControllerSliceTest`(6 케이스), `AdminEndUserIntegrationTest`(검색·집계·격리·count 정합성). |
```

- [ ] **Step 3: Commit**

```bash
cd /Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/admin-end-user-views
git add docs/architecture.md
git commit -m "$(cat <<'EOF'
docs: record Admin end-user views in architecture changelog

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Backend — full check**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.slice.*" --tests "com.crosscert.passkey.integration.admin.*" --tests "com.crosscert.passkey.architecture.*" spotlessCheck`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 2: Frontend — typecheck, build, test**

Run: `cd admin && npm run typecheck && npm run build && npm test`
Expected: typecheck clean, build succeeds, 12 existing tests still pass.

- [ ] **Step 3: Manual end-to-end (optional but recommended)**

Start the stack (`server` on 8080 with `--passkey.admin.enabled=true`, the admin SPA on 5173), log in, open a tenant detail page:
- "Users" tab appears between "API Keys" and "Credentials".
- The list shows seeded end-users with active-passkey counts; the search box filters by externalId / displayName.
- Clicking a row opens `users/{id}` — the detail page shows metadata, last activity, and the user's passkey table; the "Users" tab stays active.
- As an RP_ADMIN logged into a different tenant, requesting another tenant's `/users` returns 403.

---

## Self-Review Notes

- **Spec coverage:** Repository query (§4.1) → Task 1; `lastEventForSubject` (§4.2) → Task 2; controller + endpoints (§4.3) → Task 4; DTOs (§4.4) → Task 4; frontend types (§5.1) → Task 6; list (§5.2) → Task 7; detail (§5.3) → Task 8; routing/tab (§5.4) → Task 9; slice test (§7.1) → Task 3; integration test (§7.2) → Task 5; changelog (§9 step 12) → Task 10. All spec sections mapped.
- **Type consistency:** `EndUserRow` (projection, Task 1) → consumed by `EndUserView.from` (Task 4) and the slice test's anonymous impl (Task 3) — getter names match. `EndUserView`/`EndUserDetailView` field names identical between backend records (Task 4) and frontend interfaces (Task 6). `findByTenantIdWithSearch(UUID, String, Pageable)` signature identical in Tasks 1, 3, 4, 5. `lastEventForSubject(UUID, String)` identical in Tasks 2, 3, 4.
- **Known follow-up to verify during execution:** `PageResponse.from` method name (Task 4 Step 2 verifies against `AdminTenantController`); `EmptyState`/`PageHeader`/`Button` prop shapes (Task 7 Step 2 cross-checks `CredentialsTab.tsx`); the credential-seeding path for the integration test (Task 5 Step 1 reads `TenantIsolationIntegrationTest`). These are explicit verification steps, not placeholders.
