package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.AdminTenantService;
import com.crosscert.passkey.admin.service.AdminTenantService.TenantView;
import com.crosscert.passkey.common.response.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants")
@RequiredArgsConstructor
public class AdminTenantController {

  private final AdminTenantService service;

  public record CreateTenantRequest(
      @NotBlank String name, @NotBlank @Pattern(regexp = "^[a-z][a-z0-9-]{1,62}$") String slug) {}

  @GetMapping
  public ApiResponse<List<TenantView>> list() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(service.listAll());
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ApiResponse<TenantView> create(@Valid @RequestBody CreateTenantRequest req) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(service.create(req.name(), req.slug()));
  }

  @GetMapping("/{id}")
  public ApiResponse<TenantView> get(@PathVariable UUID id) {
    AdminAuthz.requireTenantAccess(id);
    return ApiResponse.ok(service.get(id));
  }
}
