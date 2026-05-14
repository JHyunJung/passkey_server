package com.crosscert.passkey.audit.repository;

import com.crosscert.passkey.audit.domain.AuditEntry;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AuditEntryRepository extends JpaRepository<AuditEntry, AuditEntry.Pk> {

  @Query(
      "SELECT a FROM AuditEntry a WHERE a.tenantId = :tenantId ORDER BY a.createdAt DESC LIMIT 1")
  Optional<AuditEntry> findLatestForTenant(UUID tenantId);
}
