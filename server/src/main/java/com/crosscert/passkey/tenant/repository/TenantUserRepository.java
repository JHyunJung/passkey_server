package com.crosscert.passkey.tenant.repository;

import com.crosscert.passkey.tenant.domain.TenantUser;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TenantUserRepository extends JpaRepository<TenantUser, UUID> {

  Optional<TenantUser> findByExternalId(String externalId);

  long countByTenantId(UUID tenantId);

  /**
   * Row projection for the admin end-user list. {@code activeCredentialCount} comes from a
   * LEFT JOIN aggregate so the list endpoint avoids an N+1 count-per-row.
   */
  interface EndUserRow {
    UUID getId();

    String getExternalId();

    String getDisplayName();

    long getActiveCredentialCount();

    OffsetDateTime getCreatedAt();

    OffsetDateTime getUpdatedAt();
  }

  /**
   * Paged end-user listing with an optional case-insensitive substring filter over externalId and
   * displayName. {@code countQuery} is given explicitly because the main query's GROUP BY would
   * otherwise make Spring Data derive a wrong count. Passing {@code null}/blank {@code q} returns
   * the full tenant page.
   */
  @Query(
      value =
          "SELECT u.id AS id, u.externalId AS externalId, u.displayName AS displayName, "
              + "u.createdAt AS createdAt, u.updatedAt AS updatedAt, "
              + "COUNT(c.id) AS activeCredentialCount "
              + "FROM TenantUser u "
              + "LEFT JOIN com.crosscert.passkey.credential.domain.Credential c "
              + "  ON c.tenantUserId = u.id "
              + "  AND c.status = com.crosscert.passkey.credential.domain.CredentialStatus.ACTIVE "
              + "WHERE u.tenantId = :tenantId "
              + "  AND (:q IS NULL "
              + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
              + "       OR LOWER(COALESCE(u.displayName, '')) LIKE LOWER(CONCAT('%', :q, '%'))) "
              + "GROUP BY u.id, u.externalId, u.displayName, u.createdAt, u.updatedAt",
      countQuery =
          "SELECT COUNT(u) FROM TenantUser u "
              + "WHERE u.tenantId = :tenantId "
              + "  AND (:q IS NULL "
              + "       OR LOWER(u.externalId) LIKE LOWER(CONCAT('%', :q, '%')) "
              + "       OR LOWER(COALESCE(u.displayName, '')) LIKE LOWER(CONCAT('%', :q, '%')))")
  Page<EndUserRow> findByTenantIdWithSearch(
      @Param("tenantId") UUID tenantId, @Param("q") String q, Pageable pageable);
}
