package com.crosscert.passkey.credential.repository;

import com.crosscert.passkey.credential.domain.Credential;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

  // findByCredentialId(String) intentionally omitted — every code path that accepts a
  // credentialId from a client MUST bind the tenant explicitly. RLS/VPD still gates the query,
  // but a mis-set tenant context or any use of the app_admin BYPASS-role would otherwise let an
  // attacker who learned another tenant's credentialId impersonate that user. Use
  // findByCredentialIdAndTenantId below.
  Optional<Credential> findByCredentialIdAndTenantId(String credentialId, UUID tenantId);

  List<Credential> findAllByTenantUserId(UUID tenantUserId);

  /** Paged variant of {@link #findAllByTenantUserId(UUID)} for admin user-detail views. */
  Page<Credential> findAllByTenantUserId(UUID tenantUserId, Pageable pageable);

  Page<Credential> findAllByTenantId(UUID tenantId, Pageable pageable);

  long countByTenantIdAndStatus(
      UUID tenantId, com.crosscert.passkey.credential.domain.CredentialStatus status);

  /** Count credentials of a single user with a given status. Used for admin user-detail summary. */
  long countByTenantUserIdAndStatus(
      UUID tenantUserId, com.crosscert.passkey.credential.domain.CredentialStatus status);

  /** Status → count for a single user. Used for admin user-detail summary in a single query. */
  @Query(
      "SELECT c.status AS status, COUNT(c) AS count "
          + "FROM Credential c "
          + "WHERE c.tenantUserId = :userId "
          + "GROUP BY c.status")
  List<StatusCountRow> countByTenantUserIdGroupedByStatus(@Param("userId") UUID userId);

  /**
   * Latest {@code lastUsedAt} across all credentials of one user. Used to enrich the admin
   * user-detail "last activity" timestamp — {@code CREDENTIAL_AUTHENTICATED} audit rows are keyed
   * on the credential id, not the tenant_user_id, so a pure audit lookup misses ordinary login
   * activity. A single aggregate query is cheap and avoids loading the whole credential list.
   * Returns {@code null} when the user has no credentials, or no credential has been used yet.
   */
  @Query("SELECT MAX(c.lastUsedAt) FROM Credential c WHERE c.tenantUserId = :userId")
  java.time.OffsetDateTime maxLastUsedAtByTenantUserId(@Param("userId") UUID userId);

  /** Projection for {@link #countByTenantUserIdGroupedByStatus}. */
  interface StatusCountRow {
    com.crosscert.passkey.credential.domain.CredentialStatus getStatus();

    long getCount();
  }

  /** Group-by aggregate for the credentials stats panel. {@code aaguid} may be null. */
  interface AaguidCount {
    String getAaguid();

    long getCount();
  }

  /** Group-by aggregate keyed on the revoked_reason column ({@code null} for active rows). */
  interface ReasonCount {
    String getReason();

    long getCount();
  }

  @Query(
      "SELECT c.aaguid AS aaguid, COUNT(c) AS count FROM Credential c "
          + "WHERE c.tenantId = :tenantId GROUP BY c.aaguid ORDER BY COUNT(c) DESC")
  List<AaguidCount> aaguidDistribution(@Param("tenantId") UUID tenantId);

  @Query(
      "SELECT CAST(c.revokedReason AS string) AS reason, COUNT(c) AS count FROM Credential c "
          + "WHERE c.tenantId = :tenantId GROUP BY c.revokedReason ORDER BY COUNT(c) DESC")
  List<ReasonCount> revokedReasonDistribution(@Param("tenantId") UUID tenantId);

  /**
   * Paged listing with optional substring filter (P2-4). Matches against externalUserId (joined via
   * TenantUser), credentialId, or nickname — all case-insensitive. Passing {@code null} / blank for
   * {@code q} returns the full tenant page (same as {@link #findAllByTenantId}).
   */
  @Query(
      "SELECT c FROM Credential c, com.crosscert.passkey.tenant.domain.TenantUser u "
          + "WHERE c.tenantId = :tenantId "
          + "  AND c.tenantUserId = u.id "
          + "  AND (:q IS NULL "
          + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
          + "       OR LOWER(c.credentialId) LIKE LOWER(CONCAT('%', :q, '%')) "
          + "       OR LOWER(COALESCE(c.nickname, '')) LIKE LOWER(CONCAT('%', :q, '%')))")
  Page<Credential> findByTenantIdWithSearch(
      @Param("tenantId") UUID tenantId, @Param("q") String q, Pageable pageable);

  /**
   * Cross-tenant reassignment (rare). Native UPDATE because {@code tenant_id} is non-updatable on
   * the JPA entity. The caller must verify rpId compatibility and have PLATFORM_OPERATOR rights;
   * RLS still applies, so a runtime-only deployment will see 0 affected rows unless the source
   * tenant context is set. Use the {@code app_admin} datasource for cross-tenant moves.
   */
  @Modifying
  @Query(
      value =
          "UPDATE credential "
              + "   SET tenant_id = :targetTenantId, "
              + "       tenant_user_id = :targetTenantUserId, "
              + "       updated_at = SYSTIMESTAMP "
              + " WHERE id = :credentialId "
              + "   AND tenant_id = :sourceTenantId",
      nativeQuery = true)
  int reassignTenant(
      @Param("credentialId") UUID credentialId,
      @Param("sourceTenantId") UUID sourceTenantId,
      @Param("targetTenantId") UUID targetTenantId,
      @Param("targetTenantUserId") UUID targetTenantUserId);
}
