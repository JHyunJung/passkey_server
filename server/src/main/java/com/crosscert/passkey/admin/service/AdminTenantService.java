package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.PageResponse;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.Tenant;
import com.crosscert.passkey.tenant.domain.TenantStatus;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminTenantService {

  private final TenantRepository tenantRepo;
  private final AuditService auditService;
  private final ApiKeyRepository apiKeyRepo;
  private final RefreshTokenRepository refreshRepo;

  public record TenantView(UUID id, String name, String slug, String status) {
    static TenantView from(Tenant t) {
      return new TenantView(t.getId(), t.getName(), t.getSlug(), t.getStatus().name());
    }
  }

  @Transactional(readOnly = true)
  public PageResponse<TenantView> listAll(Pageable pageable) {
    // Platform-operator scoped — assumes the controller already enforced role.
    return PageResponse.from(tenantRepo.findAll(pageable).map(TenantView::from));
  }

  @Transactional
  public TenantView create(String name, String slug) {
    if (tenantRepo.findBySlug(slug).isPresent()) {
      throw new BusinessException(ErrorCode.TENANT_SLUG_DUPLICATE);
    }
    Tenant saved = tenantRepo.save(Tenant.create(name, slug));
    // Defer the audit append until after the outer transaction commits — otherwise the audit
    // row's REQUIRES_NEW transaction runs on a separate connection that cannot yet see the new
    // tenant row, and the audit_log → tenant FK fails the entire request.
    try {
      TenantContextHolder.set(new TenantContext(saved.getId(), saved.getSlug()));
      auditService.appendAfterCommit(
          AuditEventType.TENANT_CREATED,
          ActorType.ADMIN,
          null,
          "TENANT",
          saved.getId().toString(),
          Map.of("name", name, "slug", slug));
    } finally {
      TenantContextHolder.clear();
    }
    log.info("admin.tenant.created tenantId={} slug={} name={}", saved.getId(), slug, name);
    return TenantView.from(saved);
  }

  @Transactional(readOnly = true)
  public TenantView get(UUID tenantId) {
    Tenant t =
        tenantRepo
            .findById(tenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.TENANT_NOT_FOUND));
    return TenantView.from(t);
  }

  /**
   * Platform-operator action (P3-1): toggle tenant status. Suspending also bulk-revokes every API
   * key and refresh token of the tenant so RP traffic is blocked within the API-key cache TTL (≈ 5
   * min). Activating only flips the status — operator must re-issue API keys explicitly.
   */
  @Transactional
  public TenantView updateStatus(UUID tenantId, String requestedStatus) {
    Tenant tenant =
        tenantRepo
            .findById(tenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.TENANT_NOT_FOUND));
    TenantStatus next;
    try {
      next = TenantStatus.valueOf(requestedStatus.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new BusinessException(ErrorCode.INVALID_INPUT, "invalid status: " + requestedStatus);
    }
    if (next != TenantStatus.ACTIVE && next != TenantStatus.SUSPENDED) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "status must be ACTIVE or SUSPENDED (use DELETE for purge)");
    }

    try {
      TenantContextHolder.set(new TenantContext(tenantId, "admin-tenant-status:" + tenantId));
      switch (next) {
        case SUSPENDED -> {
          tenant.suspend();
          int keysRevoked = apiKeyRepo.revokeAllByTenantId(tenantId);
          int tokensRevoked =
              refreshRepo.revokeAllByTenantId(
                  tenantId, RevokedReason.ADMIN_FORCED, OffsetDateTime.now(ZoneOffset.UTC));
          auditService.append(
              AuditEventType.TENANT_SUSPENDED,
              ActorType.ADMIN,
              null,
              "TENANT",
              tenantId.toString(),
              Map.of("apiKeysRevoked", keysRevoked, "refreshTokensRevoked", tokensRevoked));
          log.warn(
              "admin.tenant.suspended tenantId={} apiKeysRevoked={} refreshTokensRevoked={}",
              tenantId,
              keysRevoked,
              tokensRevoked);
        }
        case ACTIVE -> {
          tenant.activate();
          auditService.append(
              AuditEventType.TENANT_ACTIVATED,
              ActorType.ADMIN,
              null,
              "TENANT",
              tenantId.toString(),
              Map.of());
          log.info("admin.tenant.activated tenantId={}", tenantId);
        }
        default -> throw new BusinessException(ErrorCode.INVALID_INPUT, "unreachable");
      }
    } finally {
      TenantContextHolder.clear();
    }
    return TenantView.from(tenant);
  }
}
