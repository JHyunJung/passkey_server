package com.crosscert.passkey.admin.domain;

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
 * Admin console user. RLS-exempt — login lookup runs before tenant context is established.
 * Authorization (RP_ADMIN can only touch their own tenant) is enforced in the application layer.
 */
@Getter
@Entity
@Table(name = "admin_user")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AdminUser extends BaseEntity {

  /** NULL for PLATFORM_OPERATOR. */
  @Column(name = "tenant_id")
  private UUID tenantId;

  @Column(name = "email", nullable = false, unique = true)
  private String email;

  @Column(name = "password_hash", nullable = false)
  private String passwordHash;

  @Column(name = "display_name", nullable = false)
  private String displayName;

  @Enumerated(EnumType.STRING)
  @Column(name = "role", nullable = false)
  private AdminRole role;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false)
  private AdminStatus status;

  @Column(name = "last_login_at")
  private OffsetDateTime lastLoginAt;

  private AdminUser(
      UUID id,
      UUID tenantId,
      String email,
      String passwordHash,
      String displayName,
      AdminRole role) {
    super(id);
    this.tenantId = tenantId;
    this.email = email;
    this.passwordHash = passwordHash;
    this.displayName = displayName;
    this.role = role;
    this.status = AdminStatus.ACTIVE;
  }

  public static AdminUser createPlatformOperator(
      String email, String passwordHash, String displayName) {
    return new AdminUser(
        UUID.randomUUID(), null, email, passwordHash, displayName, AdminRole.PLATFORM_OPERATOR);
  }

  public static AdminUser createRpAdmin(
      UUID tenantId, String email, String passwordHash, String displayName) {
    return new AdminUser(
        UUID.randomUUID(), tenantId, email, passwordHash, displayName, AdminRole.RP_ADMIN);
  }

  public boolean isActive() {
    return this.status == AdminStatus.ACTIVE;
  }

  public boolean isPlatformOperator() {
    return this.role == AdminRole.PLATFORM_OPERATOR;
  }

  public void recordLogin() {
    this.lastLoginAt = OffsetDateTime.now(ZoneOffset.UTC);
  }

  public void suspend() {
    this.status = AdminStatus.SUSPENDED;
  }

  public void resetPassword(String newPasswordHash) {
    this.passwordHash = newPasswordHash;
  }
}
