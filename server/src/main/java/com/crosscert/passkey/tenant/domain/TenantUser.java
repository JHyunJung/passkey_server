package com.crosscert.passkey.tenant.domain;

import com.crosscert.passkey.infrastructure.jpa.TenantScopedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(
    name = "tenant_user",
    schema = "passkey",
    uniqueConstraints =
        @UniqueConstraint(
            name = "uk_tenant_user__tenant_external",
            columnNames = {"tenant_id", "external_id"}))
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TenantUser extends TenantScopedEntity {

  @Column(name = "external_id", nullable = false)
  private String externalId;

  @Column(name = "display_name")
  private String displayName;

  private TenantUser(UUID id, UUID tenantId, String externalId, String displayName) {
    super(id, tenantId);
    this.externalId = externalId;
    this.displayName = displayName;
  }

  /** Create with explicit tenantId — used by admin paths and tests. */
  public static TenantUser create(UUID tenantId, String externalId, String displayName) {
    return new TenantUser(UUID.randomUUID(), tenantId, externalId, displayName);
  }

  /** Create using the ambient tenant context — used by RP-facing paths. */
  public static TenantUser create(String externalId, String displayName) {
    return new TenantUser(UUID.randomUUID(), null, externalId, displayName);
  }

  public void rename(String displayName) {
    this.displayName = displayName;
  }
}
