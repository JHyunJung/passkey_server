package com.crosscert.passkey.credential.controller;

import com.crosscert.passkey.auth.jwt.TokenPair;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.api.RefreshRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Stateful refresh-token rotation endpoint.
 *
 * <p>Lives under {@code /api/v1/rp/auth/**} so it sits behind the RP API-key chain — the X-API-Key
 * header authenticates the RP backend. The end-user proof is the refresh token itself (signature +
 * DB row not revoked). The token's {@code tid} claim is the source of truth for the tenant binding;
 * we don't reach into {@code TenantContextHolder} directly so the controller stays within ArchUnit
 * Rule 2's allow-list.
 */
@RestController
@RequestMapping("/api/v1/rp/auth")
@RequiredArgsConstructor
public class RpAuthRefreshController {

  private final TokenService tokenService;

  @PostMapping("/refresh")
  public ApiResponse<TokenPair> refresh(
      @Valid @RequestBody RefreshRequest body, HttpServletRequest req) {
    String ip = req.getRemoteAddr();
    String ua = req.getHeader("User-Agent");
    return ApiResponse.ok(tokenService.rotate(body.refreshToken(), ip, ua));
  }
}
