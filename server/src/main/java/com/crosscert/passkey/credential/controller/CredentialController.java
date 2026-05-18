package com.crosscert.passkey.credential.controller;

import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.api.RpCredentialRenameRequest;
import com.crosscert.passkey.credential.service.CredentialLifecycleService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/rp/passkeys")
@RequiredArgsConstructor
public class CredentialController {

  private final CredentialLifecycleService lifecycle;

  @GetMapping
  public ApiResponse<List<CredentialView>> list(
      @RequestParam("externalUserId") String externalUserId) {
    return ApiResponse.ok(lifecycle.listForUser(externalUserId));
  }

  /**
   * Renames the caller's own credential. {@code externalUserId} is required in the body so the
   * server can verify within-tenant ownership — RP-facing auth (X-API-Key) only proves the tenant,
   * not the end user. BREAKING: prior versions accepted only {@code nickname}.
   */
  @PatchMapping("/{id}")
  public ApiResponse<CredentialView> rename(
      @PathVariable UUID id, @Valid @RequestBody RpCredentialRenameRequest req) {
    return ApiResponse.ok(lifecycle.renameForUser(id, req.externalUserId(), req.nickname()));
  }

  /**
   * Revokes the caller's own credential. {@code externalUserId} is required as a query parameter —
   * DELETE bodies are unreliable across HTTP clients and proxies. BREAKING: prior versions accepted
   * a bare {@code DELETE /{id}}.
   */
  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public ApiResponse<Void> revoke(
      @PathVariable UUID id, @RequestParam("externalUserId") String externalUserId) {
    lifecycle.revokeForUser(id, externalUserId);
    return ApiResponse.ok();
  }
}
