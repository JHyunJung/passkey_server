package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.AdminPlatformStatsService;
import com.crosscert.passkey.admin.service.AdminPlatformStatsService.PlatformStats;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cross-tenant platform statistics for PLATFORM_OPERATOR. The aggregate spans every tenant, so it
 * is computed by {@link AdminPlatformStatsService} on the VPD-exempt {@code APP_ADMIN} data source
 * — {@link AdminAuthz#requirePlatformOperator()} deliberately does NOT set {@code
 * TenantContextHolder}.
 *
 * <p>Conditional on {@code passkey.admin.enabled=true}: depends on the admin data source.
 */
@RestController
@RequestMapping("/api/v1/admin/platform")
@RequiredArgsConstructor
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
@Tag(
    name = "Admin · Platform",
    description = "Cross-tenant platform-wide aggregate stats. PLATFORM_OPERATOR only.")
public class AdminPlatformStatsController {

  /** Serialised view of the platform-wide aggregate counters. */
  public record PlatformStatsView(long activeCredentials, long activeApiKeys, long ceremonies24h) {}

  private final AdminPlatformStatsService statsService;

  @GetMapping("/stats")
  @Operation(
      summary = "Platform-wide stats",
      description =
          "Aggregate active credentials, active API keys, and trailing-24h ceremony starts across all tenants.")
  public ApiResponse<PlatformStatsView> stats() {
    AdminAuthz.requirePlatformOperator();
    PlatformStats stats = statsService.compute();
    return ApiResponse.ok(
        new PlatformStatsView(
            stats.activeCredentials(), stats.activeApiKeys(), stats.ceremonies24h()));
  }
}
