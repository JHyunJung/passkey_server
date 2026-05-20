package com.crosscert.passkey.demo.web;

import com.crosscert.passkey.demo.user.DemoUser;
import com.crosscert.passkey.demo.user.InMemoryUserStore;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Account creation — RP-owned, outside the passkey SDK's scope. The Client calls this first to get
 * an {@code externalUserId}, then uses that id to start a passkey registration ceremony.
 */
@RestController
public class SignupController {

  private final InMemoryUserStore userStore;

  public SignupController(InMemoryUserStore userStore) {
    this.userStore = userStore;
  }

  @PostMapping("/users")
  public DemoUser signup(@RequestBody SignupRequest req) {
    return userStore.create(req.displayName());
  }

  public record SignupRequest(String displayName) {}
}
