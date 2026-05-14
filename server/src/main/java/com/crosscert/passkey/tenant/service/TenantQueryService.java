package com.crosscert.passkey.tenant.service;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.domain.Tenant;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TenantQueryService {

  private final TenantRepository tenantRepository;

  /** Resolve tenant by UUID or slug. Returns empty if not found. */
  @Transactional(readOnly = true)
  public Optional<TenantContext> findActive(String identifier) {
    return resolveTenant(identifier).filter(Tenant::isActive).map(this::toContext);
  }

  /** Strict lookup — throws if not found or not active. */
  @Transactional(readOnly = true)
  public TenantContext requireActive(String identifier) {
    Tenant tenant =
        resolveTenant(identifier)
            .orElseThrow(() -> new BusinessException(ErrorCode.TENANT_NOT_FOUND));
    if (!tenant.isActive()) {
      throw new BusinessException(ErrorCode.TENANT_INACTIVE);
    }
    return toContext(tenant);
  }

  private Optional<Tenant> resolveTenant(String identifier) {
    if (identifier == null || identifier.isBlank()) {
      return Optional.empty();
    }
    return tryParseUuid(identifier)
        .flatMap(tenantRepository::findById)
        .or(() -> tenantRepository.findBySlug(identifier));
  }

  private Optional<UUID> tryParseUuid(String s) {
    try {
      return Optional.of(UUID.fromString(s));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private TenantContext toContext(Tenant t) {
    return new TenantContext(t.getId(), t.getSlug());
  }
}
