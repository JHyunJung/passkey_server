package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.service.AuditAggregationService;
import com.crosscert.passkey.auth.apikey.domain.ApiKeyStatus;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Tenant overview "vital signs" — single round trip behind {@code /tenants/:id/overview} that
 * powers the dashboard cards. Same counting rules as {@code AdminFunnelController}, just over a
 * fixed 24-hour window.
 */
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}")
@RequiredArgsConstructor
@Tag(name = "Admin · Tenant Overview", description = "Dashboard vital signs for a single tenant.")
public class AdminTenantOverviewController {

  private final CredentialRepository credentialRepo;
  private final TenantUserRepository tenantUserRepo;
  private final ApiKeyRepository apiKeyRepo;
  private final AuditAggregationService auditAgg;

  public record Ceremonies24h(
      long registrationStarted,
      long registrationCompleted,
      long authenticationAttempted,
      long authenticationSucceeded) {}

  public record OverviewStatsView(
      long activeCredentials,
      long activeUsers,
      long activeApiKeys,
      Ceremonies24h ceremonies24h,
      OffsetDateTime lastAuditAt) {}

  @GetMapping("/overview-stats")
  @Transactional(readOnly = true)
  @Operation(
      summary = "Overview vital signs",
      description =
          "Counts (creds/users/api-keys) + ceremony funnel over the last 24h + last audit timestamp.")
  public ApiResponse<OverviewStatsView> get(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);

    long activeCreds = credentialRepo.countByTenantIdAndStatus(tenantId, CredentialStatus.ACTIVE);
    long activeUsers = tenantUserRepo.countByTenantId(tenantId);
    long activeApiKeys = apiKeyRepo.countByTenantIdAndStatus(tenantId, ApiKeyStatus.ACTIVE);

    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    OffsetDateTime from = now.minusHours(24);

    Map<String, Long> byType = auditAgg.countByType(tenantId, from, now);
    long regDone = byType.getOrDefault("CREDENTIAL_REGISTERED", 0L);
    long authOk = byType.getOrDefault("CREDENTIAL_AUTHENTICATED", 0L);
    Ceremonies24h ceremonies =
        new Ceremonies24h(
            Math.max(byType.getOrDefault("REGISTRATION_OPTIONS_REQUESTED", 0L), regDone),
            regDone,
            Math.max(byType.getOrDefault("AUTHENTICATION_OPTIONS_REQUESTED", 0L), authOk),
            authOk);

    OffsetDateTime lastAuditAt = auditAgg.lastEventAt(tenantId).orElse(null);

    return ApiResponse.ok(
        new OverviewStatsView(activeCreds, activeUsers, activeApiKeys, ceremonies, lastAuditAt));
  }
}
