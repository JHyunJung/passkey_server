package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.metadata.MdsBlobProvider;
import com.crosscert.passkey.credential.metadata.MdsDiagController;
import com.crosscert.passkey.credential.metadata.MdsProperties;
import com.crosscert.passkey.ratelimit.RateLimitFilter;
import io.micrometer.core.instrument.MeterRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * System-wide operations exposed to PLATFORM_OPERATOR through the authenticated admin filter chain
 * — mirror of selected {@code /_diag} endpoints that the runbook recommends blocking at the load
 * balancer. Each handler delegates into the shared helper on {@link MdsDiagController} so the
 * payload shape stays in lock-step.
 *
 * <p>None of these endpoints write to {@code audit_log}: the chain is per-tenant and RLS-isolated,
 * so platform-level events would have no chain to land in. We rely on structured logs + the
 * Micrometer counter {@code passkey.system.mds.refresh} for observability.
 */
@RestController
@RequestMapping("/api/v1/admin/system")
@RequiredArgsConstructor
@Tag(
    name = "Admin · System",
    description =
        "Platform-level operations (MDS status/refresh, rate-limit snapshot). PLATFORM_OPERATOR only.")
public class AdminSystemController {

  private final MdsProperties mdsProps;
  private final ObjectProvider<MdsBlobProvider> mdsProviderProvider;
  private final MeterRegistry meterRegistry;
  private final RateLimitFilter rateLimitFilter;

  @GetMapping("/mds/status")
  @Operation(
      summary = "FIDO MDS status",
      description = "Returns enabled flag, lastFetched, nextUpdate, entryCount.")
  public ApiResponse<Map<String, Object>> mdsStatus() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(
        MdsDiagController.buildStatusPayload(mdsProps, mdsProviderProvider.getIfAvailable()));
  }

  @PostMapping("/mds/refresh")
  @Operation(
      summary = "Force MDS BLOB refresh",
      description =
          "Synchronously refetches and re-verifies the MDS3 BLOB; bumps the passkey.system.mds.refresh counter.")
  public ApiResponse<Map<String, Object>> mdsRefresh() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(
        MdsDiagController.forceRefresh(
            mdsProps, mdsProviderProvider.getIfAvailable(), meterRegistry));
  }

  @GetMapping("/rate-limit")
  @Operation(summary = "Rate-limit snapshot", description = "Current per-bucket consumption.")
  public ApiResponse<RateLimitFilter.Snapshot> rateLimit() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(rateLimitFilter.snapshot());
  }
}
