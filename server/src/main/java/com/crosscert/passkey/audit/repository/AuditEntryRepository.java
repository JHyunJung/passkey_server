package com.crosscert.passkey.audit.repository;

import com.crosscert.passkey.audit.domain.AuditEntry;
import com.crosscert.passkey.audit.domain.AuditEventType;
import jakarta.persistence.QueryHint;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.hibernate.jpa.HibernateHints;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;

public interface AuditEntryRepository extends JpaRepository<AuditEntry, AuditEntry.Pk> {

  @Query(
      "SELECT a FROM AuditEntry a WHERE a.tenantId = :tenantId ORDER BY a.createdAt DESC LIMIT 1")
  Optional<AuditEntry> findLatestForTenant(UUID tenantId);

  /**
   * Streams audit entries for a tenant in chain order (ascending by createdAt, then id as a stable
   * tiebreaker). Must be invoked inside a transaction; the caller is responsible for closing the
   * stream so the underlying JDBC ResultSet is released.
   */
  @QueryHints({@QueryHint(name = HibernateHints.HINT_FETCH_SIZE, value = "1000")})
  @Query(
      "SELECT a FROM AuditEntry a WHERE a.tenantId = :tenantId "
          + "AND a.createdAt >= :from AND a.createdAt < :to "
          + "ORDER BY a.createdAt ASC, a.id ASC")
  Stream<AuditEntry> streamForTenantByTime(UUID tenantId, OffsetDateTime from, OffsetDateTime to);

  /**
   * Paged listing with optional eventType filter (P2-4). {@code null} eventType returns every row
   * for the tenant — the partial-index in V9 already covers the funnel events; other event types
   * fall back to the {@code tenant_id + created_at} index which exists on the partitioned table.
   */
  @Query(
      "SELECT a FROM AuditEntry a WHERE a.tenantId = :tenantId "
          + "AND (:eventType IS NULL OR a.eventType = :eventType)")
  Page<AuditEntry> findByTenantIdAndOptionalEventType(
      @Param("tenantId") UUID tenantId,
      @Param("eventType") AuditEventType eventType,
      Pageable pageable);
}
