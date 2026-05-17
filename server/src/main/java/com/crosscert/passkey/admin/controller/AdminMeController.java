package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/me")
@Tag(name = "Admin · Me", description = "Authenticated admin self info.")
public class AdminMeController {

  public record Me(UUID adminId, String role, UUID tenantId, String displayName) {}

  @GetMapping
  @Operation(summary = "Get current admin")
  public ApiResponse<Me> me() {
    AdminPrincipal p = AdminAuthz.currentPrincipal();
    return ApiResponse.ok(new Me(p.adminId(), p.role().name(), p.tenantId(), p.displayName()));
  }
}
