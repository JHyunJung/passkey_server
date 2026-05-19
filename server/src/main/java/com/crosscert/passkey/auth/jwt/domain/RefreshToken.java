package com.crosscert.passkey.auth.jwt.domain;

import com.crosscert.passkey.infrastructure.jpa.TenantScopedEntity;
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
 * Per-issued refresh-token record. The {@code id} (inherited from {@link TenantScopedEntity}/
 * BaseEntity) doubles as the JWT {@code jti} claim — knowing the jti is enough to revoke the token
 * server-side.
 *
 * <p>Lifecycle: ACTIVE → (rotate ⇒ revokedReason=ROTATED + new row with parent_jti=this.id) or
 * (revoke ⇒ revokedReason=…). Reuse detection: if a refresh request presents a token whose row is
 * already revoked, the entire family (everything sharing the same root jti) is burned.
 */
@Getter
@Entity
@Table(name = "refresh_token")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken extends TenantScopedEntity {

  @Column(name = "tenant_user_id", nullable = false, updatable = false)
  private UUID tenantUserId;

  /** Previous jti (for rotation lineage). NULL on first issuance. */
  @Column(name = "parent_jti", updatable = false)
  private UUID parentJti;

  @Column(name = "issued_at", nullable = false, updatable = false)
  private OffsetDateTime issuedAt;

  @Column(name = "expires_at", nullable = false, updatable = false)
  private OffsetDateTime expiresAt;

  @Column(name = "revoked_at")
  private OffsetDateTime revokedAt;

  @Enumerated(EnumType.STRING)
  @Column(name = "revoked_reason")
  private RevokedReason revokedReason;

  @Column(name = "client_ip", updatable = false)
  private String clientIp;

  @Column(name = "user_agent", updatable = false)
  private String userAgent;

  private RefreshToken(
      UUID jti,
      UUID tenantId,
      UUID tenantUserId,
      UUID parentJti,
      OffsetDateTime issuedAt,
      OffsetDateTime expiresAt,
      String clientIp,
      String userAgent) {
    super(jti, tenantId);
    this.tenantUserId = tenantUserId;
    this.parentJti = parentJti;
    this.issuedAt = issuedAt;
    this.expiresAt = expiresAt;
    this.clientIp = clientIp;
    this.userAgent = userAgent;
  }

  public static RefreshToken create(
      UUID jti,
      UUID tenantId,
      UUID tenantUserId,
      UUID parentJti,
      OffsetDateTime expiresAt,
      String clientIp,
      String userAgent) {
    return new RefreshToken(
        jti,
        tenantId,
        tenantUserId,
        parentJti,
        OffsetDateTime.now(ZoneOffset.UTC),
        expiresAt,
        truncate(clientIp, 64),
        truncate(userAgent, 256));
  }

  public boolean isRevoked() {
    return this.revokedAt != null;
  }

  public boolean isExpired() {
    return OffsetDateTime.now(ZoneOffset.UTC).isAfter(this.expiresAt);
  }

  public boolean isActive() {
    return !isRevoked() && !isExpired();
  }

  public void revoke(RevokedReason reason) {
    if (this.revokedAt != null) {
      return; // idempotent
    }
    this.revokedAt = OffsetDateTime.now(ZoneOffset.UTC);
    this.revokedReason = reason;
  }

  /** Returns the lineage root jti (oldest ancestor). */
  public UUID rootJti() {
    return this.parentJti == null ? this.getId() : this.parentJti;
  }

  private static String truncate(String s, int max) {
    if (s == null) return null;
    return s.length() <= max ? s : s.substring(0, max);
  }
}
