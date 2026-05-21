package com.crosscert.passkey.demo.web;

import com.crosscert.passkey.demo.user.DemoUser;
import com.crosscert.passkey.demo.user.InMemoryUserStore;
import com.crosscert.passkey.demo.web.error.DemoBusinessException;
import com.crosscert.passkey.rp.dto.ApiResponse;
import com.crosscert.passkey.rp.starter.security.PasskeyPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A protected business endpoint. The SDK's JWT filter has already verified the bearer token and
 * injected {@link PasskeyPrincipal} — the demo just maps {@code externalUserId} back to its own
 * user record. No token parsing, no security wiring written here.
 *
 * <p>Success and failure both surface through the unified {@link ApiResponse} envelope — the happy
 * path returns {@code ApiResponse.ok}, error paths throw {@link DemoBusinessException} which {@code
 * DemoExceptionHandler} converts into the same envelope.
 */
@RestController
public class MeController {

  private final InMemoryUserStore userStore;

  public MeController(InMemoryUserStore userStore) {
    this.userStore = userStore;
  }

  @GetMapping("/me")
  public ApiResponse<DemoUser> me(@AuthenticationPrincipal PasskeyPrincipal principal) {
    if (principal == null) {
      throw DemoBusinessException.unauthorized();
    }
    DemoUser user =
        userStore
            .findByExternalUserId(principal.externalUserId())
            .orElseThrow(DemoBusinessException::userNotFound);
    return ApiResponse.ok(user);
  }
}
