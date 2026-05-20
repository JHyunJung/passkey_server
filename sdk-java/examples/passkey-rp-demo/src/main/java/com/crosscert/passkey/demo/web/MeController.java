package com.crosscert.passkey.demo.web;

import com.crosscert.passkey.demo.user.DemoUser;
import com.crosscert.passkey.demo.user.InMemoryUserStore;
import com.crosscert.passkey.rp.starter.security.PasskeyPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A protected business endpoint. The SDK's JWT filter has already verified the bearer token and
 * injected {@link PasskeyPrincipal} — the demo just maps {@code externalUserId} back to its own
 * user record. No token parsing, no security wiring written here.
 */
@RestController
public class MeController {

  private final InMemoryUserStore userStore;

  public MeController(InMemoryUserStore userStore) {
    this.userStore = userStore;
  }

  @GetMapping("/me")
  public ResponseEntity<DemoUser> me(@AuthenticationPrincipal PasskeyPrincipal principal) {
    if (principal == null) {
      return ResponseEntity.status(401).build();
    }
    return userStore
        .findByExternalUserId(principal.externalUserId())
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }
}
