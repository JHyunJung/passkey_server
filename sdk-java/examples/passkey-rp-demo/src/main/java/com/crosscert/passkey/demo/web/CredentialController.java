package com.crosscert.passkey.demo.web;

import com.crosscert.passkey.rp.client.PasskeyClient;
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
 */
@RestController
public class CredentialController {

  private final PasskeyClient passkeyClient;

  public CredentialController(PasskeyClient passkeyClient) {
    this.passkeyClient = passkeyClient;
  }

  @GetMapping("/credentials")
  public List<CredentialView> list(
      @AuthenticationPrincipal PasskeyPrincipal principal, HttpServletRequest request) {
    return passkeyClient.listCredentials(principal.externalUserId(), request);
  }

  @PatchMapping("/credentials/{id}")
  public CredentialView rename(
      @PathVariable UUID id,
      @RequestBody RenameRequest req,
      @AuthenticationPrincipal PasskeyPrincipal principal,
      HttpServletRequest request) {
    return passkeyClient.renameCredential(id, principal.externalUserId(), req.nickname(), request);
  }

  @DeleteMapping("/credentials/{id}")
  public void revoke(
      @PathVariable UUID id,
      @AuthenticationPrincipal PasskeyPrincipal principal,
      HttpServletRequest request) {
    passkeyClient.deleteCredential(id, principal.externalUserId(), request);
  }

  public record RenameRequest(String nickname) {}
}
