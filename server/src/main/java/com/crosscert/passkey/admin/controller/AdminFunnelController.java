package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/funnel")
public class AdminFunnelController {

  @PersistenceContext EntityManager em;

  public record FunnelView(
      long registrationStarted,
      long registrationCompleted,
      long authenticationAttempted,
      long authenticationSucceeded) {}

  @GetMapping
  @Transactional(readOnly = true)
  @SuppressWarnings("unchecked")
  public ApiResponse<FunnelView> get(
      @PathVariable UUID tenantId,
      @RequestParam(required = false) OffsetDateTime from,
      @RequestParam(required = false) OffsetDateTime to) {
    AdminAuthz.requireTenantAccess(tenantId);

    OffsetDateTime fromTs = from == null ? OffsetDateTime.now().minusDays(7) : from;
    OffsetDateTime toTs = to == null ? OffsetDateTime.now() : to;

    var counts =
        (java.util.List<Object[]>)
            em.createNativeQuery(
                    """
                    SELECT event_type, count(*)
                      FROM passkey.audit_log
                     WHERE tenant_id = :tenantId
                       AND created_at >= :fromTs
                       AND created_at <  :toTs
                     GROUP BY event_type
                    """)
                .setParameter("tenantId", tenantId)
                .setParameter("fromTs", fromTs)
                .setParameter("toTs", toTs)
                .getResultList();

    Map<String, Long> byType = new java.util.HashMap<>();
    for (Object[] row : counts) {
      byType.put((String) row[0], ((Number) row[1]).longValue());
    }
    long regDone = byType.getOrDefault("CREDENTIAL_REGISTERED", 0L);
    long authOk = byType.getOrDefault("CREDENTIAL_AUTHENTICATED", 0L);

    // Without a separate "options started" event we approximate started == completed; M5 hardening
    // will introduce explicit ceremony-start audit events to compute drop-off accurately.
    return ApiResponse.ok(new FunnelView(regDone, regDone, authOk, authOk));
  }
}
