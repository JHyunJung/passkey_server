package com.crosscert.passkey.tenant.controller;

import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.util.HashMap;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Local/dev-only diagnostics. Exposed at {@code /_diag/**} and excluded from production by profile.
 */
@RestController
@RequestMapping("/_diag")
@Profile({"local", "dev"})
public class DiagnosticsController {

  @GetMapping("/whoami")
  public ApiResponse<Map<String, Object>> whoami() {
    Map<String, Object> body = new HashMap<>();
    TenantContextHolder.optional()
        .ifPresentOrElse(
            ctx -> {
              body.put("tenantId", ctx.tenantId().toString());
              body.put("tenantSlug", ctx.tenantSlug());
              body.put("resolved", true);
            },
            () -> body.put("resolved", false));
    return ApiResponse.ok(body);
  }
}
