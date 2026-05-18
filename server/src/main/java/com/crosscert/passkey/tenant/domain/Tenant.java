package com.crosscert.passkey.tenant.domain;

import com.crosscert.passkey.infrastructure.jpa.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "tenant")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Tenant extends BaseEntity {

  @Column(name = "name", nullable = false)
  private String name;

  @Column(name = "slug", nullable = false, unique = true)
  private String slug;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false)
  private TenantStatus status;

  private Tenant(UUID id, String name, String slug, TenantStatus status) {
    super(id);
    this.name = name;
    this.slug = slug;
    this.status = status;
  }

  public static Tenant create(String name, String slug) {
    return new Tenant(UUID.randomUUID(), name, slug, TenantStatus.ACTIVE);
  }

  public boolean isActive() {
    return this.status == TenantStatus.ACTIVE;
  }

  public void suspend() {
    this.status = TenantStatus.SUSPENDED;
  }

  public void activate() {
    this.status = TenantStatus.ACTIVE;
  }
}
