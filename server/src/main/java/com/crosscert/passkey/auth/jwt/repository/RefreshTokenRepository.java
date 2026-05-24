package com.crosscert.passkey.auth.jwt.repository;

import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

  Optional<RefreshToken> findByIdAndTenantUserId(UUID jti, UUID tenantUserId);

  /**
   * Active = not revoked AND not yet expired. Sorted by {@code issuedAt} desc — newest sessions
   * surface at the top of the admin Sessions tab.
   */
  @Query(
      "SELECT r FROM RefreshToken r "
          + " WHERE r.tenantUserId = :userId AND r.revokedAt IS NULL AND r.expiresAt > :now "
          + " ORDER BY r.issuedAt DESC")
  Page<RefreshToken> findActiveByTenantUserId(
      @Param("userId") UUID tenantUserId, @Param("now") OffsetDateTime now, Pageable pageable);

  /**
   * All states (active, expired, revoked) for the user, sorted by {@code issuedAt} desc. Used by
   * the admin Sessions-tab "All" filter for forensic review.
   */
  @Query("SELECT r FROM RefreshToken r WHERE r.tenantUserId = :userId ORDER BY r.issuedAt DESC")
  Page<RefreshToken> findAllByTenantUserId(@Param("userId") UUID tenantUserId, Pageable pageable);

  /** Active-session count for the admin user-detail summary card. */
  @Query(
      "SELECT COUNT(r) FROM RefreshToken r "
          + " WHERE r.tenantUserId = :userId AND r.revokedAt IS NULL AND r.expiresAt > :now")
  long countActiveByTenantUserId(
      @Param("userId") UUID tenantUserId, @Param("now") OffsetDateTime now);

  /**
   * Bulk-revoke every active token of a user. Used on credential revoke / admin force-logout.
   * Returns affected row count for audit logging.
   */
  @Modifying
  @Query(
      "UPDATE RefreshToken r "
          + "   SET r.revokedAt = :now, r.revokedReason = :reason "
          + " WHERE r.tenantUserId = :userId AND r.revokedAt IS NULL")
  int revokeAllByTenantUserId(
      @Param("userId") UUID tenantUserId,
      @Param("reason") RevokedReason reason,
      @Param("now") OffsetDateTime now);

  /**
   * Burn every row in a rotation family — the rooted jti and any descendant whose parent_jti chains
   * back to it. Used on REUSE_DETECTED.
   */
  @Modifying
  @Query(
      "UPDATE RefreshToken r "
          + "   SET r.revokedAt = :now, r.revokedReason = :reason "
          + " WHERE r.tenantUserId = :userId "
          + "   AND r.revokedAt IS NULL "
          + "   AND (r.id = :rootJti OR r.parentJti = :rootJti)")
  int revokeFamily(
      @Param("userId") UUID tenantUserId,
      @Param("rootJti") UUID rootJti,
      @Param("reason") RevokedReason reason,
      @Param("now") OffsetDateTime now);

  /** Cleanup hook — delete tokens that expired more than {@code grace} ago. */
  @Modifying
  @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :before")
  int deleteExpiredBefore(@Param("before") OffsetDateTime before);

  /**
   * Bulk-revoke every active token of a tenant. Used by tenant suspend (P3-1). The tenant filter is
   * pinned on the tenantId column so this runs cleanly with or without RLS.
   */
  @Modifying
  @Query(
      "UPDATE RefreshToken r "
          + "   SET r.revokedAt = :now, r.revokedReason = :reason "
          + " WHERE r.tenantId = :tenantId AND r.revokedAt IS NULL")
  int revokeAllByTenantId(
      @Param("tenantId") UUID tenantId,
      @Param("reason") RevokedReason reason,
      @Param("now") OffsetDateTime now);
}
