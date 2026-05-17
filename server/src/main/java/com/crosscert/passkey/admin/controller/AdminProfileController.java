package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.AdminUserManagementService;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Self-service profile actions for the authenticated admin (P2-2). */
@RestController
@RequestMapping("/api/v1/admin/me")
@RequiredArgsConstructor
@Tag(name = "Admin · Profile", description = "Self-service password change for the current admin.")
public class AdminProfileController {

  private final AdminUserManagementService service;

  public record ChangeMyPasswordRequest(
      @NotBlank String oldPassword, @NotBlank @Size(min = 12, max = 128) String newPassword) {}

  @PostMapping("/password")
  @Operation(summary = "Change own password", description = "Requires old password verification.")
  public ApiResponse<Void> changeOwnPassword(@Valid @RequestBody ChangeMyPasswordRequest req) {
    var adminId = AdminAuthz.currentPrincipal().adminId();
    service.changeOwnPassword(adminId, req.oldPassword(), req.newPassword());
    return ApiResponse.ok();
  }
}
