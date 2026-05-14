package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.AdminTenantService;
import com.crosscert.passkey.admin.service.AdminTenantService.TenantView;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
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
public class AdminTenantController {

  private final AdminTenantService service;

  public record CreateTenantRequest(
      @NotBlank String name, @NotBlank @Pattern(regexp = "^[a-z][a-z0-9-]{1,62}$") String slug) {}

  @GetMapping
  public ApiResponse<PageResponse<TenantView>> list(
      @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
    AdminAuthz.requirePlatformOperator();
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "slug"));
    return ApiResponse.ok(service.listAll(pageable));
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
