package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.service.CredentialLifecycleService;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
  public ApiResponse<PageResponse<CredentialView>> list(
      @PathVariable UUID tenantId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size) {
    AdminAuthz.requireTenantAccess(tenantId);
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    return ApiResponse.ok(
        PageResponse.from(repo.findAllByTenantId(tenantId, pageable).map(CredentialView::from)));
  }

  @DeleteMapping("/{credentialId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public ApiResponse<Void> revoke(@PathVariable UUID tenantId, @PathVariable UUID credentialId) {
    AdminAuthz.requireTenantAccess(tenantId);
    lifecycle.revoke(credentialId);
    return ApiResponse.ok();
  }
}
