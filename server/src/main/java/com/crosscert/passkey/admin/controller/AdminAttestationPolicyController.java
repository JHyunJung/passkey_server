package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.domain.AttestationMode;
import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
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
public class AdminAttestationPolicyController {

  private final TenantAttestationPolicyRepository repo;

  public record PolicyView(String mode, List<String> allowed, List<String> denied) {
    static PolicyView from(TenantAttestationPolicy p) {
      return new PolicyView(
          p.getMode().name(), csvOrEmpty(p.getAllowedAaguids()), csvOrEmpty(p.getDeniedAaguids()));
    }
  }

  public record UpsertRequest(
      @NotBlank String mode, List<String> allowedAaguids, List<String> deniedAaguids) {}

  @GetMapping
  @Transactional(readOnly = true)
  public ApiResponse<PolicyView> get(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantAttestationPolicy p =
        repo.findByTenantId(tenantId)
            .orElseGet(() -> repo.save(TenantAttestationPolicy.permissive(tenantId)));
    return ApiResponse.ok(PolicyView.from(p));
  }

  @PutMapping
  @Transactional
  public ApiResponse<PolicyView> upsert(
      @PathVariable UUID tenantId, @Valid @RequestBody UpsertRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    AttestationMode mode = AttestationMode.valueOf(req.mode());
    TenantAttestationPolicy policy =
        repo.findByTenantId(tenantId)
            .orElseGet(() -> repo.save(TenantAttestationPolicy.permissive(tenantId)));
    policy.update(mode, req.allowedAaguids(), req.deniedAaguids());
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
