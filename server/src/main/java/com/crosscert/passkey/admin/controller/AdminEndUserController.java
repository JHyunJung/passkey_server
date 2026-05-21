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
 * Read-only end-user (tenant_user) listing and detail. Shares the {@code
 * /api/v1/admin/tenants/{tenantId}/users} base path with {@code AdminUserSessionController}
 * (force-logout) — no conflict, the methods/sub-paths differ. Both PLATFORM_OPERATOR and the
 * tenant's own RP_ADMIN may read, enforced by {@link AdminAuthz#requireTenantAccess}.
 */
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/users")
@RequiredArgsConstructor
@Tag(
    name = "Admin · End Users",
    description = "Per-tenant end-user listing and detail (read-only).")
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
    long activeCount = credentials.stream().filter(c -> "ACTIVE".equals(c.status())).count();
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
