package com.crosscert.passkey.rp.starter.web;

import com.crosscert.passkey.rp.client.PasskeyClient;
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
 * Drop-in controller that exposes the five RP-facing endpoints under {@code /passkey/**} so the
 * host app immediately has a working backend for the browser SDK. Gated by {@code
 * passkey.rp.ceremony.controller-enabled=true} (default true). Disable when the RP wants to wire
 * its own controllers.
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
  public RegistrationOptionsResponse registerBegin(
      @RequestBody RegistrationBeginRequest req, HttpServletRequest http) {
    return client.beginRegistration(req, http);
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/register/finish")
  public RegistrationResult registerFinish(
      @RequestBody RegistrationVerifyRequest req, HttpServletRequest http) {
    return client.finishRegistration(req, http);
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/authenticate/begin")
  public AuthenticationOptionsResponse authBegin(
      @RequestBody AuthenticationOptionsRequest req, HttpServletRequest http) {
    return client.beginAuthentication(req, http);
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/authenticate/finish")
  public AuthenticationResult authFinish(
      @RequestBody AuthenticationVerifyRequest req, HttpServletRequest http) {
    AuthenticationResult result = client.finishAuthentication(req, http);
    PasskeySessionAuthenticationSuccessHandler handler = sessionHandler.getIfAvailable();
    if (handler != null && props.getAuth().getMode() == PasskeyProperties.Auth.Mode.SESSION) {
      handler.onSuccess(http, result);
    }
    return result;
  }

  @PostMapping("${passkey.rp.ceremony.path-prefix:/passkey}/refresh")
  public RefreshResult refresh(@RequestBody RefreshRequest req, HttpServletRequest http) {
    return refreshManager.refresh(req.refreshToken(), http);
  }
}
