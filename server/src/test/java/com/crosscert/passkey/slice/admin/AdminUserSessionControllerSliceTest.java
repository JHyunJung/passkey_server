package com.crosscert.passkey.slice.admin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.controller.AdminUserSessionController;
import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.GlobalExceptionHandler;
import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies the force-logout endpoint enforces tenant ownership, calls the bulk-revoke repo with
 * {@link RevokedReason#ADMIN_FORCED}, and writes a {@code USER_FORCE_LOGOUT} audit row.
 */
@WebMvcTest(
    controllers = AdminUserSessionController.class,
    excludeAutoConfiguration = {
      org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
      org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
    })
@Import({GlobalExceptionHandler.class, TraceIdFilter.class})
class AdminUserSessionControllerSliceTest {

  @Autowired MockMvc mvc;
  @MockBean TenantUserRepository tenantUserRepo;
  @MockBean RefreshTokenRepository refreshTokenRepo;
  @MockBean AuditService auditService;

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void force_logout_revokes_tokens_and_appends_audit() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    TenantUser user = TenantUser.create(tenantId, "ext-1", "Alice");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));
    when(refreshTokenRepo.revokeAllByTenantUserId(
            eq(tenantUserId), eq(RevokedReason.ADMIN_FORCED), any(OffsetDateTime.class)))
        .thenReturn(3);

    mvc.perform(
            post(
                "/api/v1/admin/tenants/{tenantId}/users/{userId}/logout-all",
                tenantId,
                tenantUserId))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.revokedCount").value(3));

    verify(auditService)
        .append(
            eq(AuditEventType.USER_FORCE_LOGOUT),
            any(),
            any(),
            eq("TENANT_USER"),
            eq(tenantUserId.toString()),
            any());
  }

  @Test
  void force_logout_rejects_cross_tenant_user() throws Exception {
    UUID pathTenantId = UUID.randomUUID();
    UUID otherTenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    // user belongs to a different tenant than the URL — must reject with INVALID_INPUT.
    TenantUser user = TenantUser.create(otherTenantId, "ext-2", "Bob");
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.of(user));

    mvc.perform(
            post(
                "/api/v1/admin/tenants/{tenantId}/users/{userId}/logout-all",
                pathTenantId,
                tenantUserId))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("C001"));

    verify(refreshTokenRepo, never()).revokeAllByTenantUserId(any(), any(), any());
  }

  @Test
  void force_logout_returns_404_when_user_missing() throws Exception {
    UUID tenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.PLATFORM_OPERATOR, null);
    when(tenantUserRepo.findById(tenantUserId)).thenReturn(Optional.empty());

    mvc.perform(
            post(
                "/api/v1/admin/tenants/{tenantId}/users/{userId}/logout-all",
                tenantId,
                tenantUserId))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("C003"));
  }

  @Test
  void force_logout_rejected_when_rp_admin_targets_other_tenant() throws Exception {
    UUID pathTenantId = UUID.randomUUID();
    UUID rpAdminTenantId = UUID.randomUUID();
    UUID tenantUserId = UUID.randomUUID();
    loginAs(AdminRole.RP_ADMIN, rpAdminTenantId);

    mvc.perform(
            post(
                "/api/v1/admin/tenants/{tenantId}/users/{userId}/logout-all",
                pathTenantId,
                tenantUserId))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));

    verify(tenantUserRepo, never()).findById(any());
  }

  private static void loginAs(AdminRole role, UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, role, "ops@local", "Ops");
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities()));
  }
}
