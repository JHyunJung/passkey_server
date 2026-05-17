package com.crosscert.passkey.auth.apikey.repository;

import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

  Optional<ApiKey> findByPrefix(String prefix);

  List<ApiKey> findAllByTenantId(UUID tenantId);

  long countByTenantIdAndStatus(
      UUID tenantId, com.crosscert.passkey.auth.apikey.domain.ApiKeyStatus status);

  /**
   * Bulk-revoke every active key of a tenant. Used by tenant suspend (P3-1). Returns affected row
   * count for audit logging. Caffeine caches still hit until TTL (5 min) — call {@code
   * ApiKeyRevocationPublisher.publishAll(tenantId)} alongside if immediate cross-instance eviction
   * is required.
   */
  @Modifying
  @Query(
      "UPDATE ApiKey k SET k.status = "
          + "  com.crosscert.passkey.auth.apikey.domain.ApiKeyStatus.REVOKED "
          + "WHERE k.tenantId = :tenantId "
          + "  AND k.status = com.crosscert.passkey.auth.apikey.domain.ApiKeyStatus.ACTIVE")
  int revokeAllByTenantId(@Param("tenantId") UUID tenantId);
}
