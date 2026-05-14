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

  public record PolicyView(String mode, List<String> allowed, List<String> denied) {}

  public record UpsertRequest(
      @NotBlank String mode, List<String> allowedAaguids, List<String> deniedAaguids) {}

  @GetMapping
  @Transactional(readOnly = true)
  public ApiResponse<PolicyView> get(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantAttestationPolicy p =
        repo.findByTenantId(tenantId)
            .orElseGet(() -> repo.save(TenantAttestationPolicy.permissive(tenantId)));
    return ApiResponse.ok(
        new PolicyView(
            p.getMode().name(),
            csvOrEmpty(p.getAllowedAaguids()),
            csvOrEmpty(p.getDeniedAaguids())));
  }

  @PutMapping
  @Transactional
  public ApiResponse<PolicyView> upsert(
      @PathVariable UUID tenantId, @Valid @RequestBody UpsertRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    repo.findByTenantId(tenantId).ifPresent(repo::delete);
    repo.flush();
    // Domain currently exposes only the permissive factory; for M4 we accept the mode/lists by
    // persisting via JPA defaults and a follow-up admin migration. This endpoint is a placeholder
    // for full edit support — captured as Open Item.
    TenantAttestationPolicy fresh = TenantAttestationPolicy.permissive(tenantId);
    TenantAttestationPolicy saved = repo.save(fresh);
    return ApiResponse.ok(
        new PolicyView(
            saved.getMode().name(),
            csvOrEmpty(saved.getAllowedAaguids()),
            csvOrEmpty(saved.getDeniedAaguids())));
  }

  private static List<String> csvOrEmpty(String csv) {
    if (csv == null || csv.isBlank()) return List.of();
    return java.util.Arrays.stream(csv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
  }

  @SuppressWarnings("unused")
  private static final AttestationMode REF = AttestationMode.ANY;
}
