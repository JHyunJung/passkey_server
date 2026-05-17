package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import com.crosscert.passkey.credential.api.CredentialRenameRequest;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.domain.CredentialRevokedReason;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.service.CredentialLifecycleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin-facing credential management.
 *
 * <p><b>DTO policy.</b> Admin controllers declare their request/response DTOs as inner records by
 * default — keeps each admin endpoint self-contained and surfaces breaking changes via Java
 * compile-time errors instead of subtle cross-domain coupling. The only exception is reuse of
 * RP-facing DTOs that represent the same conceptual entity ({@link CredentialView}, {@link
 * CredentialRenameRequest} here): duplicating them would force two-sided edits whenever the
 * credential shape changes. New admin DTOs must default to inner records.
 */
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/credentials")
@RequiredArgsConstructor
@Tag(
    name = "Admin · Credentials",
    description = "Per-tenant passkey credential listing, stats, rename, revoke, reassign.")
public class AdminCredentialController {

  private final CredentialRepository repo;
  private final CredentialLifecycleService lifecycle;

  public record ReassignRequest(@NotNull UUID targetTenantId, @NotNull UUID targetTenantUserId) {}

  public record CredentialStatsView(
      List<Map<String, Object>> aaguid, List<Map<String, Object>> revokedReason) {}

  @GetMapping("/stats")
  @Transactional(readOnly = true)
  @Operation(
      summary = "Credential distribution stats",
      description = "AAGUID + revoked-reason histograms for the tenant overview dashboard.")
  public ApiResponse<CredentialStatsView> stats(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    List<Map<String, Object>> aaguid =
        repo.aaguidDistribution(tenantId).stream()
            .map(
                row ->
                    Map.<String, Object>of(
                        "aaguid",
                        row.getAaguid() == null ? "unknown" : row.getAaguid(),
                        "count",
                        row.getCount()))
            .toList();
    List<Map<String, Object>> reasons =
        repo.revokedReasonDistribution(tenantId).stream()
            .map(
                row ->
                    Map.<String, Object>of(
                        "reason",
                        row.getReason() == null ? "ACTIVE" : row.getReason(),
                        "count",
                        row.getCount()))
            .toList();
    return ApiResponse.ok(new CredentialStatsView(aaguid, reasons));
  }

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(
      summary = "List credentials",
      description = "Paginated, newest first. Optional fuzzy search by ?q=.")
  public ApiResponse<PageResponse<CredentialView>> list(
      @PathVariable UUID tenantId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size,
      @RequestParam(required = false) String q) {
    AdminAuthz.requireTenantAccess(tenantId);
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    String trimmed = q == null || q.isBlank() ? null : q.trim();
    var page0 =
        trimmed == null
            ? repo.findAllByTenantId(tenantId, pageable)
            : repo.findByTenantIdWithSearch(tenantId, trimmed, pageable);
    return ApiResponse.ok(PageResponse.from(page0.map(CredentialView::from)));
  }

  /** Admin rename — useful during incident response to tag suspect credentials. */
  @PatchMapping("/{credentialId}/nickname")
  @Operation(summary = "Rename credential (admin override)")
  public ApiResponse<CredentialView> rename(
      @PathVariable UUID tenantId,
      @PathVariable UUID credentialId,
      @Valid @RequestBody CredentialRenameRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    return ApiResponse.ok(lifecycle.rename(credentialId, req.nickname()));
  }

  /**
   * Cross-tenant reassignment (rare). Only allowed when source and target tenants share the same
   * {@code rpId} — otherwise the credential would be unusable post-move. PLATFORM_OPERATOR only.
   */
  @PostMapping("/{credentialId}/reassign")
  @Operation(
      summary = "Reassign credential cross-tenant",
      description =
          "Requires source and target tenants to share the same rpId. PLATFORM_OPERATOR only.")
  public ApiResponse<CredentialView> reassign(
      @PathVariable UUID tenantId,
      @PathVariable UUID credentialId,
      @Valid @RequestBody ReassignRequest req) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(
        lifecycle.reassign(credentialId, tenantId, req.targetTenantId(), req.targetTenantUserId()));
  }

  @DeleteMapping("/{credentialId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(
      summary = "Revoke credential",
      description = "Reason defaults to ADMIN_FORCED when omitted.")
  public ApiResponse<Void> revoke(
      @PathVariable UUID tenantId,
      @PathVariable UUID credentialId,
      @RequestParam(name = "reason", required = false) CredentialRevokedReason reason) {
    AdminAuthz.requireTenantAccess(tenantId);
    lifecycle.revoke(credentialId, reason == null ? CredentialRevokedReason.ADMIN_FORCED : reason);
    return ApiResponse.ok();
  }
}
