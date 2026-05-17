package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.domain.AdminUser;
import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.AdminUserManagementService;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * AdminUser CRUD for PLATFORM_OPERATOR (P2-2). Password change for the caller themselves lives in
 * {@link AdminProfileController}.
 */
@RestController
@RequestMapping("/api/v1/admin/admins")
@RequiredArgsConstructor
@Tag(
    name = "Admin · Admin Users",
    description = "PLATFORM_OPERATOR-only CRUD for admin accounts + temporary password reset.")
public class AdminAdminUserController {

  private final AdminUserManagementService service;

  public record AdminUserView(
      UUID id,
      String email,
      String displayName,
      String role,
      UUID tenantId,
      String status,
      OffsetDateTime lastLoginAt,
      OffsetDateTime createdAt) {
    static AdminUserView from(AdminUser u) {
      return new AdminUserView(
          u.getId(),
          u.getEmail(),
          u.getDisplayName(),
          u.getRole().name(),
          u.getTenantId(),
          u.getStatus().name(),
          u.getLastLoginAt(),
          u.getCreatedAt());
    }
  }

  public record CreateAdminRequest(
      @Email @NotBlank String email,
      @NotBlank String displayName,
      @NotNull AdminRole role,
      UUID tenantId) {}

  public record CreatedAdminView(AdminUserView admin, String temporaryPassword) {}

  @GetMapping
  @Operation(summary = "List admin users")
  public ApiResponse<PageResponse<AdminUserView>> list(
      @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
    AdminAuthz.requirePlatformOperator();
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "email"));
    return ApiResponse.ok(PageResponse.from(service.list(pageable).map(AdminUserView::from)));
  }

  @GetMapping("/{id}")
  @Operation(summary = "Get admin user by id")
  public ApiResponse<AdminUserView> get(@PathVariable UUID id) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(AdminUserView.from(service.get(id)));
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Create admin user",
      description =
          "Returns a one-shot temporary password; the new admin must change it on first login.")
  public ApiResponse<CreatedAdminView> create(@Valid @RequestBody CreateAdminRequest req) {
    AdminAuthz.requirePlatformOperator();
    UUID actor = AdminAuthz.currentPrincipal().adminId();
    var created = service.create(req.email(), req.displayName(), req.role(), req.tenantId(), actor);
    return ApiResponse.ok(
        new CreatedAdminView(AdminUserView.from(created.admin()), created.temporaryPassword()));
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Delete admin user", description = "Self-delete is forbidden (M004).")
  public ApiResponse<Void> delete(@PathVariable UUID id) {
    AdminAuthz.requirePlatformOperator();
    UUID actor = AdminAuthz.currentPrincipal().adminId();
    service.delete(id, actor);
    return ApiResponse.ok();
  }

  public record ResetPasswordView(String temporaryPassword) {}

  @PostMapping("/{id}/password")
  @Operation(
      summary = "Reset admin password",
      description = "Returns a one-shot temporary password. Self-reset is forbidden.")
  public ApiResponse<ResetPasswordView> resetPassword(@PathVariable UUID id) {
    AdminAuthz.requirePlatformOperator();
    UUID actor = AdminAuthz.currentPrincipal().adminId();
    String temp = service.resetPassword(id, actor);
    return ApiResponse.ok(new ResetPasswordView(temp));
  }
}
