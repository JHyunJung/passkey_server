package com.crosscert.passkey.demo.web;

import com.crosscert.passkey.demo.web.error.DemoBusinessException;
import com.crosscert.passkey.rp.client.PasskeyClient;
import com.crosscert.passkey.rp.dto.ApiResponse;
import com.crosscert.passkey.rp.dto.CredentialView;
import com.crosscert.passkey.rp.starter.security.PasskeyPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Credential management — list / rename / revoke the signed-in user's passkeys.
 *
 * <p>The SDK ships {@link PasskeyClient} with these methods but no controller for them, so the RP
 * wraps each in one line. {@code externalUserId} is taken from the verified {@link
 * PasskeyPrincipal}, never from the request body — a Client cannot manage another user's passkeys.
 *
 * <p>Every response is wrapped in the unified {@link ApiResponse} envelope — the same schema the
 * passkey platform uses — so a Client parses RP-backend and platform responses identically.
 */
@RestController
public class CredentialController {

  private final PasskeyClient passkeyClient;

  public CredentialController(PasskeyClient passkeyClient) {
    this.passkeyClient = passkeyClient;
  }

  @GetMapping("/credentials")
  public ApiResponse<List<CredentialView>> list(
      @AuthenticationPrincipal PasskeyPrincipal principal, HttpServletRequest request) {
    return ApiResponse.ok(passkeyClient.listCredentials(externalUserId(principal), request));
  }

  @PatchMapping("/credentials/{id}")
  public ApiResponse<CredentialView> rename(
      @PathVariable UUID id,
      @RequestBody RenameRequest req,
      @AuthenticationPrincipal PasskeyPrincipal principal,
      HttpServletRequest request) {
    return ApiResponse.ok(
        passkeyClient.renameCredential(id, externalUserId(principal), req.nickname(), request));
  }

  @DeleteMapping("/credentials/{id}")
  public ApiResponse<Void> revoke(
      @PathVariable UUID id,
      @AuthenticationPrincipal PasskeyPrincipal principal,
      HttpServletRequest request) {
    passkeyClient.deleteCredential(id, externalUserId(principal), request);
    return ApiResponse.ok();
  }

  /**
   * Pulls {@code externalUserId} from the verified principal, or throws a 401 in the unified
   * envelope when the JWT filter injected none — so an unauthenticated call never surfaces as a raw
   * 500.
   */
  private static String externalUserId(PasskeyPrincipal principal) {
    if (principal == null) {
      throw DemoBusinessException.unauthorized();
    }
    return principal.externalUserId();
  }

  public record RenameRequest(String nickname) {}
}
