package com.crosscert.passkey.ratelimit;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies per-tenant + per-endpoint-class rate limits after tenant resolution. {@code
 * /api/v1/rp/passkeys/register/*} and {@code .../authenticate/*} have stricter buckets than the
 * default; everything else falls back to a generic limit.
 */
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

  private final RateLimitProperties props;
  private final RateLimiter limiter;

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!props.enabled()) {
      return true;
    }
    String uri = request.getRequestURI();
    return uri.startsWith("/actuator") || uri.startsWith("/_diag");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    String tenantSegment =
        TenantContextHolder.optional()
            .map(c -> c.tenantId().toString())
            .orElse("anon:" + req.getRemoteAddr());

    int limit = pickLimit(req.getRequestURI());
    String bucket = tenantSegment + ":" + classifyPath(req.getRequestURI());
    if (!limiter.tryAcquire(bucket, limit)) {
      throw new BusinessException(ErrorCode.RATE_LIMIT_EXCEEDED);
    }
    chain.doFilter(req, res);
  }

  private int pickLimit(String uri) {
    if (uri.startsWith("/api/v1/rp/passkeys/register")) {
      return props.registrationPerMinute();
    }
    if (uri.startsWith("/api/v1/rp/passkeys/authenticate")) {
      return props.authenticationPerMinute();
    }
    // v1.1: /api/v1/admin/auth/login should have a dedicated, stricter bucket keyed by source IP
    // to defeat password brute force. Today it falls under defaultPerMinute.
    return props.defaultPerMinute();
  }

  private String classifyPath(String uri) {
    if (uri.startsWith("/api/v1/rp/passkeys/register")) {
      return "register";
    }
    if (uri.startsWith("/api/v1/rp/passkeys/authenticate")) {
      return "authenticate";
    }
    return "default";
  }
}
