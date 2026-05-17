package com.crosscert.passkey.ratelimit;

import com.crosscert.passkey.common.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only diagnostics for the in-process rate limiter. Exposed under {@code /_diag/**}, which is
 * always {@code permitAll}; production deployments must block this prefix at the load balancer.
 *
 * <p>Mirror endpoint for authenticated operators: {@code GET /api/v1/admin/system/rate-limit}.
 */
@RestController
@RequestMapping("/_diag")
@RequiredArgsConstructor
public class RateLimitDiagController {

  private final RateLimitFilter filter;

  @GetMapping("/rate-limit-status")
  public ApiResponse<RateLimitFilter.Snapshot> rateLimitStatus() {
    return ApiResponse.ok(filter.snapshot());
  }
}
