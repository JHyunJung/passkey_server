package com.crosscert.passkey.credential.controller;

import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.api.RegistrationBeginRequest;
import com.crosscert.passkey.credential.api.RegistrationOptionsResponse;
import com.crosscert.passkey.credential.api.RegistrationResult;
import com.crosscert.passkey.credential.api.RegistrationVerifyRequest;
import com.crosscert.passkey.credential.service.RegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/rp/passkeys/register")
@RequiredArgsConstructor
public class RegistrationController {

  private final RegistrationService registrationService;

  @PostMapping("/options")
  public ApiResponse<RegistrationOptionsResponse> begin(
      @Valid @RequestBody RegistrationBeginRequest req) {
    return ApiResponse.ok(
        registrationService.beginRegistration(req.externalUserId(), req.displayName()));
  }

  @PostMapping("/verify")
  @ResponseStatus(HttpStatus.CREATED)
  public ApiResponse<RegistrationResult> verify(@Valid @RequestBody RegistrationVerifyRequest req) {
    return ApiResponse.ok(registrationService.finishRegistration(req));
  }
}
