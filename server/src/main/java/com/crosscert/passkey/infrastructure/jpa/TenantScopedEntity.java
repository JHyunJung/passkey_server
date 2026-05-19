package com.crosscert.passkey.infrastructure.jpa;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import java.util.UUID;
import lombok.Getter;

/**
 * Base type for every tenant-scoped table. {@code tenant_id} is auto-populated from {@link
 * TenantContextHolder} on insert. RLS is the final defense — this listener prevents forgetting the
 * column on the application side.
 */
@Getter
@MappedSuperclass
public abstract class TenantScopedEntity extends BaseEntity {

  // RAW(16) on Oracle; mapping is implicit via OracleDialect + java.util.UUID.
  @Column(name = "tenant_id", nullable = false, updatable = false)
  private UUID tenantId;

  protected TenantScopedEntity() {}

  protected TenantScopedEntity(UUID id, UUID tenantId) {
    super(id);
    this.tenantId = tenantId;
  }

  @PrePersist
  void onPersistTenant() {
    if (this.tenantId == null) {
      this.tenantId =
          TenantContextHolder.optional()
              .map(ctx -> ctx.tenantId())
              .orElseThrow(() -> new BusinessException(ErrorCode.TENANT_CONTEXT_MISSING));
    }
  }
}
