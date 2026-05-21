package com.crosscert.passkey.demo.web;

import com.crosscert.passkey.demo.user.DemoUser;
import com.crosscert.passkey.demo.user.InMemoryUserStore;
import com.crosscert.passkey.rp.dto.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Account creation — RP-owned, outside the passkey SDK's scope. The Client calls this first to get
 * an {@code externalUserId}, then uses that id to start a passkey registration ceremony.
 *
 * <p>Wrapped in the unified {@link ApiResponse} envelope so a Client sees one consistent schema
 * across the RP backend and the passkey platform.
 */
@RestController
public class SignupController {

  private final InMemoryUserStore userStore;

  public SignupController(InMemoryUserStore userStore) {
    this.userStore = userStore;
  }

  @PostMapping("/users")
  public ApiResponse<DemoUser> signup(@RequestBody SignupRequest req) {
    return ApiResponse.ok(userStore.create(req.displayName()));
  }

  public record SignupRequest(String displayName) {}
}
