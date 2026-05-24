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
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.GlobalExceptionHandler;
import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.metadata.AaguidLabel;
import com.crosscert.passkey.credential.metadata.AaguidLabelResolver;
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
  @MockBean RefreshTokenRepository refreshTokenRepo;
  @MockBean AuditAggregationService auditAgg;
  @MockBean AaguidLabelResolver aaguidLabelResolver;

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
  void detail_returns_counts_summary_no_inline_credentials() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-9", "Carol");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));
    when(credentialRepo.countByTenantUserIdAndStatus(tenantUserId, CredentialStatus.ACTIVE))
        .thenReturn(2L);
    when(credentialRepo.countByTenantUserIdAndStatus(tenantUserId, CredentialStatus.SUSPENDED))
        .thenReturn(1L);
    when(credentialRepo.countByTenantUserIdAndStatus(tenantUserId, CredentialStatus.REVOKED))
        .thenReturn(0L);
    when(refreshTokenRepo.countActiveByTenantUserId(eq(tenantUserId), any(OffsetDateTime.class)))
        .thenReturn(3L);
    when(auditAgg.lastEventForSubject(tenantId, tenantUserId.toString()))
        .thenReturn(Optional.of(OffsetDateTime.now(ZoneOffset.UTC)));

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users/{userId}", tenantId, tenantUserId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.externalId").value("ext-9"))
        .andExpect(jsonPath("$.data.credentials.active").value(2))
        .andExpect(jsonPath("$.data.credentials.suspended").value(1))
        .andExpect(jsonPath("$.data.credentials.revoked").value(0))
        .andExpect(jsonPath("$.data.sessions.active").value(3))
        // The old List shape is gone — the field is an object now.
        .andExpect(jsonPath("$.data.credentials[0]").doesNotExist())
        .andExpect(jsonPath("$.data.lastActivityAt").exists());
  }

  @Test
  void detail_last_activity_uses_audit_signal() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-login", "Dave");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));
    when(refreshTokenRepo.countActiveByTenantUserId(eq(tenantUserId), any(OffsetDateTime.class)))
        .thenReturn(0L);

    OffsetDateTime auditLast = OffsetDateTime.now(ZoneOffset.UTC);
    when(auditAgg.lastEventForSubject(tenantId, tenantUserId.toString()))
        .thenReturn(Optional.of(auditLast));

    mvc.perform(get("/api/v1/admin/tenants/{tenantId}/users/{userId}", tenantId, tenantUserId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.lastActivityAt").exists());
  }

  @Test
  void credentials_paged_returns_aaguid_label() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-c", "Eve");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));

    com.crosscert.passkey.credential.domain.Credential c =
        org.mockito.Mockito.mock(com.crosscert.passkey.credential.domain.Credential.class);
    when(c.getId()).thenReturn(UUID.randomUUID());
    when(c.getCredentialId()).thenReturn("abcd1234efgh");
    UUID aaguidId = UUID.randomUUID();
    when(c.getAaguid()).thenReturn(aaguidId);
    when(c.getStatus()).thenReturn(CredentialStatus.ACTIVE);
    when(c.getSuspendedReason()).thenReturn(null);
    when(c.getNickname()).thenReturn("Eve passkey");
    when(c.getCreatedAt()).thenReturn(OffsetDateTime.now(ZoneOffset.UTC));
    when(c.getLastUsedAt()).thenReturn(null);

    when(credentialRepo.findAllByTenantUserId(eq(tenantUserId), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(c), Pageable.ofSize(20), 1));
    when(aaguidLabelResolver.resolve(aaguidId))
        .thenReturn(new AaguidLabel(aaguidId, "iCloud Keychain", true));

    mvc.perform(
            get(
                "/api/v1/admin/tenants/{tenantId}/users/{userId}/credentials",
                tenantId,
                tenantUserId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content[0].credentialIdShort").value("abcd1234"))
        .andExpect(jsonPath("$.data.content[0].aaguid.displayName").value("iCloud Keychain"))
        .andExpect(jsonPath("$.data.content[0].aaguid.fromMds").value(true))
        .andExpect(jsonPath("$.data.content[0].status").value("ACTIVE"));
  }

  @Test
  void refreshTokens_default_status_active_queries_active_only() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-t", "Frank");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));
    when(refreshTokenRepo.findActiveByTenantUserId(
            eq(tenantUserId), any(OffsetDateTime.class), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(), Pageable.ofSize(20), 0));

    mvc.perform(
            get(
                "/api/v1/admin/tenants/{tenantId}/users/{userId}/refresh-tokens",
                tenantId,
                tenantUserId))
        .andExpect(status().isOk());

    verify(refreshTokenRepo)
        .findActiveByTenantUserId(eq(tenantUserId), any(OffsetDateTime.class), any(Pageable.class));
    verify(refreshTokenRepo, never()).findAllByTenantUserId(any(), any(Pageable.class));
  }

  @Test
  void refreshTokens_status_all_queries_all() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-t", "Grace");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));
    when(refreshTokenRepo.findAllByTenantUserId(eq(tenantUserId), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(), Pageable.ofSize(20), 0));

    mvc.perform(
            get(
                    "/api/v1/admin/tenants/{tenantId}/users/{userId}/refresh-tokens",
                    tenantId,
                    tenantUserId)
                .param("status", "all"))
        .andExpect(status().isOk());

    verify(refreshTokenRepo).findAllByTenantUserId(eq(tenantUserId), any(Pageable.class));
    verify(refreshTokenRepo, never())
        .findActiveByTenantUserId(any(), any(OffsetDateTime.class), any(Pageable.class));
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

    // The detail endpoint folds credentials via per-status COUNT queries; cross-tenant guard
    // must short-circuit BEFORE any of those run.
    verify(credentialRepo, never()).countByTenantUserIdAndStatus(any(), any());
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

    verify(tenantUserRepo, never()).findByTenantIdWithSearch(any(), any(), any(Pageable.class));
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
