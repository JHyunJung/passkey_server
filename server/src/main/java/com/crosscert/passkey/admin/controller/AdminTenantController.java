package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.AdminTenantService;
import com.crosscert.passkey.admin.service.AdminTenantService.TenantView;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants")
@RequiredArgsConstructor
@Tag(name = "Admin · Tenants", description = "Tenant CRUD + suspend/activate (PLATFORM_OPERATOR)")
public class AdminTenantController {

  private final AdminTenantService service;

  public record CreateTenantRequest(
      @NotBlank String name, @NotBlank @Pattern(regexp = "^[a-z][a-z0-9-]{1,62}$") String slug) {}

  public record UpdateStatusRequest(@NotBlank String status) {}

  @GetMapping
  @Operation(summary = "List tenants", description = "Paginated list, sorted by slug ASC.")
  public ApiResponse<PageResponse<TenantView>> list(
      @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
    AdminAuthz.requirePlatformOperator();
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "slug"));
    return ApiResponse.ok(service.listAll(pageable));
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Create tenant",
      description = "Slug must match ^[a-z][a-z0-9-]{1,62}$ — DNS-safe identifier.")
  public ApiResponse<TenantView> create(@Valid @RequestBody CreateTenantRequest req) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(service.create(req.name(), req.slug()));
  }

  @GetMapping("/{id}")
  @Operation(summary = "Get tenant by id")
  public ApiResponse<TenantView> get(@PathVariable UUID id) {
    AdminAuthz.requireTenantAccess(id);
    return ApiResponse.ok(service.get(id));
  }

  /**
   * Toggle tenant ACTIVE ↔ SUSPENDED (P3-1). Suspend cascades into bulk API-key + refresh-token
   * revocation. PLATFORM_OPERATOR only — RP_ADMIN never sees this control on the SPA, and the
   * server enforces the role here anyway.
   */
  @PatchMapping("/{id}/status")
  @Operation(
      summary = "Update tenant status",
      description =
          "Toggle ACTIVE ↔ SUSPENDED. Suspending cascades into bulk API-key + refresh-token revoke.")
  public ApiResponse<TenantView> updateStatus(
      @PathVariable UUID id, @Valid @RequestBody UpdateStatusRequest req) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(service.updateStatus(id, req.status()));
  }
}
