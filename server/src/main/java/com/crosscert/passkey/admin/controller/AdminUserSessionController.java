package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Force-logout endpoint for incident response — revokes every active refresh token of a given
 * tenant user in one call. Single-credential revoke does not cover users who hold multiple
 * authenticators, so this is the operator's "kill the session, not the device" lever.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/users")
@RequiredArgsConstructor
@Tag(
    name = "Admin · User Sessions",
    description = "Force-logout (refresh token mass revocation) for incident response.")
public class AdminUserSessionController {

  private final TenantUserRepository tenantUserRepo;
  private final RefreshTokenRepository refreshTokenRepo;
  private final AuditService auditService;

  public record ForceLogoutResult(int revokedCount) {}

  @PostMapping("/{tenantUserId}/logout-all")
  @Transactional
  @Operation(
      summary = "Force-logout all sessions of a user",
      description =
          "Mass-revokes every active refresh token for the user. Emits USER_FORCE_LOGOUT audit event.")
  public ApiResponse<ForceLogoutResult> forceLogout(
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
    int revoked =
        refreshTokenRepo.revokeAllByTenantUserId(
            tenantUserId, RevokedReason.ADMIN_FORCED, OffsetDateTime.now(ZoneOffset.UTC));
    auditService.append(
        AuditEventType.USER_FORCE_LOGOUT,
        ActorType.ADMIN,
        AdminAuthz.currentPrincipal().adminId().toString(),
        "TENANT_USER",
        tenantUserId.toString(),
        Map.of("revokedCount", revoked));
    log.info(
        "admin.user.forceLogout tenantId={} tenantUserId={} revokedCount={}",
        tenantId,
        tenantUserId,
        revoked);
    return ApiResponse.ok(new ForceLogoutResult(revoked));
  }
}
