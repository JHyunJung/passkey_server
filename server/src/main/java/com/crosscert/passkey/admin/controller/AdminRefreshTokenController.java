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
 * Per-session revoke. Siblings: {@code AdminUserSessionController.forceLogout} mass-revokes, {@code
 * AdminEndUserController.refreshTokens} lists. This one removes a single device while leaving the
 * user's other sessions alone — the "kick one device" lever RPs were asking for.
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
      @PathVariable UUID tenantId, @PathVariable UUID tenantUserId, @PathVariable UUID tokenId) {
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
