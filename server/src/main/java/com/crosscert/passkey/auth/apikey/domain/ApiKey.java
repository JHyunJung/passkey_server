package com.crosscert.passkey.auth.apikey.domain;

import com.crosscert.passkey.infrastructure.jpa.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * RLS-exempt — looked up by prefix before tenant context is established. Carries its own {@code
 * tenant_id} column to establish the tenant.
 */
@Getter
@Entity
@Table(name = "api_key")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ApiKey extends BaseEntity {

  @Column(name = "tenant_id", nullable = false, updatable = false)
  private UUID tenantId;

  @Column(name = "prefix", nullable = false, unique = true, updatable = false)
  private String prefix;

  @Column(name = "secret_hash", nullable = false, updatable = false)
  private String secretHash;

  @Column(name = "name", nullable = false)
  private String name;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false)
  private ApiKeyStatus status;

  @Column(name = "last_used_at")
  private OffsetDateTime lastUsedAt;

  private ApiKey(UUID id, UUID tenantId, String prefix, String secretHash, String name) {
    super(id);
    this.tenantId = tenantId;
    this.prefix = prefix;
    this.secretHash = secretHash;
    this.name = name;
    this.status = ApiKeyStatus.ACTIVE;
  }

  public static ApiKey create(UUID tenantId, String prefix, String secretHash, String name) {
    return new ApiKey(UUID.randomUUID(), tenantId, prefix, secretHash, name);
  }

  public boolean isActive() {
    return this.status == ApiKeyStatus.ACTIVE;
  }

  public void revoke() {
    this.status = ApiKeyStatus.REVOKED;
  }

  public void recordUse() {
    this.lastUsedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }
}
