package com.crosscert.passkey.credential.controller;

import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.api.AuthenticationOptionsRequest;
import com.crosscert.passkey.credential.api.AuthenticationOptionsResponse;
import com.crosscert.passkey.credential.api.AuthenticationResult;
import com.crosscert.passkey.credential.api.AuthenticationVerifyRequest;
import com.crosscert.passkey.credential.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/rp/passkeys/authenticate")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService authenticationService;

  @PostMapping("/options")
  public ApiResponse<AuthenticationOptionsResponse> begin(
      @RequestBody(required = false) AuthenticationOptionsRequest req) {
    AuthenticationOptionsRequest payload =
        req == null ? new AuthenticationOptionsRequest(null) : req;
    return ApiResponse.ok(authenticationService.beginAuthentication(payload));
  }

  @PostMapping("/verify")
  public ApiResponse<AuthenticationResult> verify(
      @Valid @RequestBody AuthenticationVerifyRequest req, HttpServletRequest httpReq) {
    String ip = httpReq.getRemoteAddr();
    String ua = httpReq.getHeader("User-Agent");
    return ApiResponse.ok(authenticationService.finishAuthentication(req, ip, ua));
  }
}
