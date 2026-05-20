package com.crosscert.passkey.rp.starter.web;

import com.crosscert.passkey.rp.client.PasskeyClient;
import com.crosscert.passkey.rp.dto.ApiResponse;
import com.crosscert.passkey.rp.dto.AuthenticationOptionsRequest;
import com.crosscert.passkey.rp.dto.AuthenticationOptionsResponse;
import com.crosscert.passkey.rp.dto.AuthenticationResult;
import com.crosscert.passkey.rp.dto.AuthenticationVerifyRequest;
import com.crosscert.passkey.rp.dto.RefreshRequest;
import com.crosscert.passkey.rp.dto.RefreshResult;
import com.crosscert.passkey.rp.dto.RegistrationBeginRequest;
import com.crosscert.passkey.rp.dto.RegistrationOptionsResponse;
import com.crosscert.passkey.rp.dto.RegistrationResult;
import com.crosscert.passkey.rp.dto.RegistrationVerifyRequest;
import com.crosscert.passkey.rp.jwt.RefreshTokenManager;
import com.crosscert.passkey.rp.starter.PasskeyProperties;
import com.crosscert.passkey.rp.starter.security.PasskeySessionAuthenticationSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Drop-in controller exposing the five RP-facing endpoints under {@code /passkey/**} so the host
 * app immediately has a working backend for the browser SDK. Gated by {@code
 * passkey.rp.ceremony.controller-enabled=true} (default true). Disable when the RP wants to wire
 * its own controllers.
 *
 * <p>Every response — success or failure (via {@link PasskeyExceptionHandler}) — is wrapped in the
 * unified {@link ApiResponse} envelope so a Client sees the same schema the passkey platform itself
 * uses.
 */
@RestController
public class PasskeyCeremonyController {

  private final PasskeyClient client;
  private final RefreshTokenManager refreshManager;
  private final ObjectProvider<PasskeySessionAuthenticationSuccessHandler> sessionHandler;
  private final PasskeyProperties props;

  public PasskeyCeremonyController(
      PasskeyClient client,
      RefreshTokenManager refreshManager,
      ObjectProvider<PasskeySessionAuthenticationSuccessHandler> sessionHandler,
      PasskeyProperties props) {
    this.client = client;
    this.refreshManager = refreshManager;
    this.sessionHandler = sessionHandler;
    this.props = props;
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/register/begin")
  public ApiResponse<RegistrationOptionsResponse> registerBegin(
      @RequestBody RegistrationBeginRequest req, HttpServletRequest http) {
    return ApiResponse.ok(client.beginRegistration(req, http));
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/register/finish")
  public ApiResponse<RegistrationResult> registerFinish(
      @RequestBody RegistrationVerifyRequest req, HttpServletRequest http) {
    return ApiResponse.ok(client.finishRegistration(req, http));
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/authenticate/begin")
  public ApiResponse<AuthenticationOptionsResponse> authBegin(
      @RequestBody AuthenticationOptionsRequest req, HttpServletRequest http) {
    return ApiResponse.ok(client.beginAuthentication(req, http));
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/authenticate/finish")
  public ApiResponse<AuthenticationResult> authFinish(
      @RequestBody AuthenticationVerifyRequest req, HttpServletRequest http) {
    AuthenticationResult result = client.finishAuthentication(req, http);
    PasskeySessionAuthenticationSuccessHandler handler = sessionHandler.getIfAvailable();
    if (handler != null && props.getAuth().getMode() == PasskeyProperties.Auth.Mode.SESSION) {
      handler.onSuccess(http, result);
    }
    return ApiResponse.ok(result);
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/refresh")
  public ApiResponse<RefreshResult> refresh(
      @RequestBody RefreshRequest req, HttpServletRequest http) {
    return ApiResponse.ok(refreshManager.refresh(req.refreshToken(), http));
  }
}
