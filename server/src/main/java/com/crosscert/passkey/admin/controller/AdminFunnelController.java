package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.service.AuditAggregationService;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/funnel")
@RequiredArgsConstructor
@Tag(
    name = "Admin · Funnel",
    description = "Registration / authentication ceremony funnel counts derived from audit log.")
public class AdminFunnelController {

  private final AuditAggregationService auditAgg;

  public record FunnelView(
      long registrationStarted,
      long registrationCompleted,
      long authenticationAttempted,
      long authenticationSucceeded) {}

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(
      summary = "Funnel counts",
      description = "Defaults to last 7 days when from/to are omitted.")
  public ApiResponse<FunnelView> get(
      @PathVariable UUID tenantId,
      @RequestParam(required = false) OffsetDateTime from,
      @RequestParam(required = false) OffsetDateTime to) {
    AdminAuthz.requireTenantAccess(tenantId);

    OffsetDateTime fromTs = from == null ? OffsetDateTime.now().minusDays(7) : from;
    OffsetDateTime toTs = to == null ? OffsetDateTime.now() : to;

    Map<String, Long> byType = auditAgg.countByType(tenantId, fromTs, toTs);

    // P2-3: dedicated start events now exist — fall back to the completion count for tenants
    // that pre-date the change so the funnel never reports started < completed (which would be a
    // negative drop-off and confuse the dashboard).
    long regDone = byType.getOrDefault("CREDENTIAL_REGISTERED", 0L);
    long authOk = byType.getOrDefault("CREDENTIAL_AUTHENTICATED", 0L);
    long regStarted = Math.max(byType.getOrDefault("REGISTRATION_OPTIONS_REQUESTED", 0L), regDone);
    long authAttempted =
        Math.max(byType.getOrDefault("AUTHENTICATION_OPTIONS_REQUESTED", 0L), authOk);

    return ApiResponse.ok(new FunnelView(regStarted, regDone, authAttempted, authOk));
  }
}
