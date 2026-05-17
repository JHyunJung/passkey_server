package com.crosscert.passkey.credential.controller;

import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.api.CredentialRenameRequest;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.domain.CredentialRevokedReason;
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

  @PatchMapping("/{id}")
  public ApiResponse<CredentialView> rename(
      @PathVariable UUID id, @Valid @RequestBody CredentialRenameRequest req) {
    return ApiResponse.ok(lifecycle.rename(id, req.nickname()));
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public ApiResponse<Void> revoke(@PathVariable UUID id) {
    // RP-facing delete is the end user choosing to drop their own passkey.
    lifecycle.revoke(id, CredentialRevokedReason.USER_REQUEST);
    return ApiResponse.ok();
  }
}
