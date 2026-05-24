package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.service.AuditAggregationService;
import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.metadata.AaguidLabel;
import com.crosscert.passkey.credential.metadata.AaguidLabelResolver;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository.EndUserRow;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
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
  private final RefreshTokenRepository refreshTokenRepo;
  private final AuditAggregationService auditAgg;
  private final AaguidLabelResolver aaguidLabelResolver;

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

  /** Per-status credential count for the user-detail summary card. */
  public record CredentialCounts(long active, long suspended, long revoked) {}

  /** Per-status session count for the user-detail summary card. */
  public record SessionCounts(long active) {}

  /**
   * End-user metadata + summary counts. No inline credentials — use the paged endpoint {@code GET
   * /users/{id}/credentials}.
   */
  public record EndUserDetailView(
      UUID id,
      String externalId,
      String displayName,
      OffsetDateTime createdAt,
      OffsetDateTime updatedAt,
      CredentialCounts credentials,
      SessionCounts sessions,
      OffsetDateTime lastActivityAt) {}

  /** One row of the per-user credentials paged endpoint (with AAGUID label). */
  public record UserCredentialItemView(
      UUID id,
      String credentialIdShort,
      AaguidLabel aaguid,
      CredentialStatus status,
      String suspendedReason,
      String nickname,
      OffsetDateTime createdAt,
      OffsetDateTime lastUsedAt) {}

  /** One row of the per-user refresh-tokens paged endpoint. */
  public record RefreshTokenView(
      UUID id,
      OffsetDateTime issuedAt,
      OffsetDateTime expiresAt,
      String clientIp,
      String userAgent,
      OffsetDateTime revokedAt,
      RevokedReason revokedReason) {}

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
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    String trimmed = (q == null || q.isBlank()) ? null : q.trim();
    return ApiResponse.ok(
        PageResponse.from(
            tenantUserRepo
                .findByTenantIdWithSearch(tenantId, trimmed, pageable)
                .map(EndUserView::from)));
  }

  @GetMapping("/{tenantUserId}")
  @Transactional(readOnly = true)
  @Operation(summary = "Get one end-user with summary counts and last-activity")
  public ApiResponse<EndUserDetailView> detail(
      @PathVariable UUID tenantId, @PathVariable UUID tenantUserId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantUser user = requireUser(tenantId, tenantUserId);

    Map<CredentialStatus, Long> counts = new EnumMap<>(CredentialStatus.class);
    for (CredentialRepository.StatusCountRow row :
        credentialRepo.countByTenantUserIdGroupedByStatus(tenantUserId)) {
      counts.put(row.getStatus(), row.getCount());
    }
    CredentialCounts cc =
        new CredentialCounts(
            counts.getOrDefault(CredentialStatus.ACTIVE, 0L),
            counts.getOrDefault(CredentialStatus.SUSPENDED, 0L),
            counts.getOrDefault(CredentialStatus.REVOKED, 0L));
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    SessionCounts sc =
        new SessionCounts(refreshTokenRepo.countActiveByTenantUserId(tenantUserId, now));

    // Inline last-credential-lastUsedAt fold is no longer cheap (credentials aren't loaded
    // here anymore — fetching them just to take max() would defeat the point of the paged
    // endpoint). Rely on the audit-aggregation last-event timestamp instead; the UI renders
    // "—" when null, identical to the previous behaviour for users with no audit signal.
    OffsetDateTime auditLast =
        auditAgg.lastEventForSubject(tenantId, tenantUserId.toString()).orElse(null);

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
            credentialRepo
                .findAllByTenantUserId(tenantUserId, pageable)
                .map(this::toCredentialRow)));
  }

  @GetMapping("/{tenantUserId}/refresh-tokens")
  @Transactional(readOnly = true)
  @Operation(summary = "Paged refresh tokens for one end-user (status=active|all)")
  public ApiResponse<PageResponse<RefreshTokenView>> refreshTokens(
      @PathVariable UUID tenantId,
      @PathVariable UUID tenantUserId,
      @RequestParam(defaultValue = "active") String status,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {
    AdminAuthz.requireTenantAccess(tenantId);
    requireUser(tenantId, tenantUserId);
    // The @Query already orders by issuedAt DESC — don't add a Sort here or Spring will
    // synthesize a second ORDER BY clause.
    Pageable pageable = PageRequest.of(page, size);
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    var pageResult =
        "all".equalsIgnoreCase(status)
            ? refreshTokenRepo.findAllByTenantUserId(tenantUserId, pageable)
            : refreshTokenRepo.findActiveByTenantUserId(tenantUserId, now, pageable);
    return ApiResponse.ok(
        PageResponse.from(pageResult.map(AdminEndUserController::toRefreshTokenRow)));
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

  private UserCredentialItemView toCredentialRow(Credential c) {
    String idShort =
        c.getCredentialId() == null
            ? null
            : c.getCredentialId().substring(0, Math.min(8, c.getCredentialId().length()));
    AaguidLabel label = aaguidLabelResolver.resolve(c.getAaguid());
    return new UserCredentialItemView(
        c.getId(),
        idShort,
        label,
        c.getStatus(),
        c.getSuspendedReason(),
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
}
