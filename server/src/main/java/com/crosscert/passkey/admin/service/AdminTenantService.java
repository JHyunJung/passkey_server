package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.PageResponse;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.Tenant;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AdminTenantService {

  private final TenantRepository tenantRepo;
  private final AuditService auditService;

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
    // Use tenant context briefly to write the audit row.
    try {
      TenantContextHolder.set(new TenantContext(saved.getId(), saved.getSlug()));
      auditService.append(
          AuditEventType.TENANT_CREATED,
          ActorType.ADMIN,
          null,
          "TENANT",
          saved.getId().toString(),
          Map.of("name", name, "slug", slug));
    } finally {
      TenantContextHolder.clear();
    }
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
}
