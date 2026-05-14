package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.service.CredentialLifecycleService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/credentials")
@RequiredArgsConstructor
public class AdminCredentialController {

  private final CredentialRepository repo;
  private final CredentialLifecycleService lifecycle;

  @GetMapping
  @Transactional(readOnly = true)
  public ApiResponse<List<CredentialView>> list(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    // RLS ensures only this tenant's rows return.
    return ApiResponse.ok(repo.findAll().stream().map(CredentialView::from).toList());
  }

  @DeleteMapping("/{credentialId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public ApiResponse<Void> revoke(@PathVariable UUID tenantId, @PathVariable UUID credentialId) {
    AdminAuthz.requireTenantAccess(tenantId);
    lifecycle.revoke(credentialId);
    return ApiResponse.ok();
  }
}
