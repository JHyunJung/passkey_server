package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.domain.AttestationMode;
import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/attestation-policy")
@RequiredArgsConstructor
@Tag(
    name = "Admin · Attestation Policy",
    description =
        "Per-tenant AAGUID allow/deny + MDS strict toggle + zero-AAGUID and syncable controls.")
public class AdminAttestationPolicyController {

  private final TenantAttestationPolicyRepository repo;

  public record PolicyView(
      String mode,
      List<String> allowed,
      List<String> denied,
      boolean mdsStrict,
      boolean allowZeroAaguid,
      boolean allowSyncable) {
    static PolicyView from(TenantAttestationPolicy p) {
      return new PolicyView(
          p.getMode().name(),
          csvOrEmpty(p.getAllowedAaguids()),
          csvOrEmpty(p.getDeniedAaguids()),
          p.isMdsStrict(),
          p.isAllowZeroAaguid(),
          p.isAllowSyncable());
    }
  }

  public record UpsertRequest(
      @NotBlank String mode,
      List<String> allowedAaguids,
      List<String> deniedAaguids,
      Boolean mdsStrict,
      Boolean allowZeroAaguid,
      Boolean allowSyncable) {}

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(
      summary = "Get attestation policy",
      description = "Returns permissive defaults if no row exists yet.")
  public ApiResponse<PolicyView> get(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantAttestationPolicy p =
        repo.findByTenantId(tenantId)
            .orElseGet(() -> repo.save(TenantAttestationPolicy.permissive(tenantId)));
    return ApiResponse.ok(PolicyView.from(p));
  }

  @PutMapping
  @Transactional
  @Operation(summary = "Update attestation policy")
  public ApiResponse<PolicyView> upsert(
      @PathVariable UUID tenantId, @Valid @RequestBody UpsertRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    AttestationMode mode = AttestationMode.valueOf(req.mode());
    TenantAttestationPolicy policy =
        repo.findByTenantId(tenantId)
            .orElseGet(() -> repo.save(TenantAttestationPolicy.permissive(tenantId)));
    boolean mdsStrict = Boolean.TRUE.equals(req.mdsStrict());
    boolean allowZero = Boolean.TRUE.equals(req.allowZeroAaguid());
    // allowSyncable defaults to true for backward compatibility when caller omits the field.
    boolean allowSyncable = req.allowSyncable() == null || req.allowSyncable();
    policy.update(
        mode, req.allowedAaguids(), req.deniedAaguids(), mdsStrict, allowZero, allowSyncable);
    return ApiResponse.ok(PolicyView.from(policy));
  }

  private static List<String> csvOrEmpty(String csv) {
    if (csv == null || csv.isBlank()) {
      return List.of();
    }
    return java.util.Arrays.stream(csv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
  }
}
