package com.crosscert.passkey.audit.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Read-only audit aggregates shared between the funnel and overview endpoints. Both consumers need
 * the same {@code event_type → count} histogram over a half-open time window, so the native query
 * lives here once instead of being copy-pasted into each controller.
 */
@Service
public class AuditAggregationService {

  @PersistenceContext private EntityManager em;

  /**
   * Histogram of audit event types for {@code tenantId} in {@code [from, to)}. Returns an empty map
   * (never null) when the tenant has no rows in the window. Caller is responsible for setting the
   * tenant RLS context — this query relies on the same row-level policy as every other read.
   */
  @Transactional(readOnly = true)
  @SuppressWarnings("unchecked")
  public Map<String, Long> countByType(UUID tenantId, OffsetDateTime from, OffsetDateTime to) {
    List<Object[]> rows =
        em.createNativeQuery(
                """
                SELECT event_type, count(*)
                  FROM audit_log
                 WHERE tenant_id = :tenantId
                   AND created_at >= :fromTs
                   AND created_at <  :toTs
                 GROUP BY event_type
                """)
            .setParameter("tenantId", tenantId)
            .setParameter("fromTs", from)
            .setParameter("toTs", to)
            .getResultList();
    Map<String, Long> byType = new HashMap<>();
    for (Object[] row : rows) {
      byType.put((String) row[0], ((Number) row[1]).longValue());
    }
    return byType;
  }

  /**
   * Timestamp of the most recent audit event for {@code tenantId}, or empty if the tenant has no
   * audit rows yet. Used by the overview "vital signs" card to display "last activity at".
   */
  @Transactional(readOnly = true)
  public Optional<OffsetDateTime> lastEventAt(UUID tenantId) {
    Object raw =
        em.createNativeQuery("SELECT MAX(created_at) FROM audit_log WHERE tenant_id = :tid")
            .setParameter("tid", tenantId)
            .getSingleResult();
    if (raw == null) {
      return Optional.empty();
    }
    if (raw instanceof OffsetDateTime odt) {
      return Optional.of(odt);
    }
    if (raw instanceof java.sql.Timestamp ts) {
      return Optional.of(ts.toInstant().atOffset(ZoneOffset.UTC));
    }
    return Optional.empty();
  }

  /**
   * Most recent audit event timestamp for a single subject (e.g. one tenant user). audit_log links
   * the subject loosely via {@code subject_id}; the caller already holds the tenant context, so the
   * tenant_id predicate keeps VPD semantics consistent with {@link #lastEventAt}.
   */
  @Transactional(readOnly = true)
  public Optional<OffsetDateTime> lastEventForSubject(UUID tenantId, String subjectId) {
    Object raw =
        em.createNativeQuery(
                "SELECT MAX(created_at) FROM audit_log "
                    + "WHERE tenant_id = :tid AND subject_id = :sid")
            .setParameter("tid", tenantId)
            .setParameter("sid", subjectId)
            .getSingleResult();
    if (raw == null) {
      return Optional.empty();
    }
    if (raw instanceof OffsetDateTime odt) {
      return Optional.of(odt);
    }
    if (raw instanceof java.sql.Timestamp ts) {
      return Optional.of(ts.toInstant().atOffset(ZoneOffset.UTC));
    }
    return Optional.empty();
  }
}
