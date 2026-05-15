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
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies per-tenant + per-endpoint-class rate limits after tenant resolution. Stricter buckets for
 * {@code register}, {@code authenticate}, and {@code admin-login} (the latter keyed by source IP to
 * defeat password brute force); everything else falls back to a generic limit.
 */
@Slf4j
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

  private static final int ADMIN_LOGIN_PER_MINUTE = 5;

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
    int limit = pickLimit(req.getRequestURI());
    String bucket = bucketKey(req);
    if (!limiter.tryAcquire(bucket, limit)) {
      log.warn(
          "ratelimit.exceeded bucket={} limit={} path={} ip={}",
          bucket,
          limit,
          req.getRequestURI(),
          req.getRemoteAddr());
      throw new BusinessException(ErrorCode.RATE_LIMIT_EXCEEDED);
    }
    chain.doFilter(req, res);
  }

  private String bucketKey(HttpServletRequest req) {
    String classification = classifyPath(req.getRequestURI());
    if ("admin-login".equals(classification)) {
      // Pre-auth path → key by client IP. Email-derived key requires reading the body which we
      // can't safely do here; IP bucket is sufficient for v1 brute-force defence.
      return "ip:" + req.getRemoteAddr() + ":admin-login";
    }
    String tenantSegment =
        TenantContextHolder.optional()
            .map(c -> c.tenantId().toString())
            .orElse("anon:" + req.getRemoteAddr());
    return tenantSegment + ":" + classification;
  }

  private int pickLimit(String uri) {
    if (uri.startsWith("/api/v1/rp/passkeys/register")) {
      return props.registrationPerMinute();
    }
    if (uri.startsWith("/api/v1/rp/passkeys/authenticate")) {
      return props.authenticationPerMinute();
    }
    if (uri.startsWith("/api/v1/admin/auth/login")) {
      return ADMIN_LOGIN_PER_MINUTE;
    }
    return props.defaultPerMinute();
  }

  private String classifyPath(String uri) {
    if (uri.startsWith("/api/v1/rp/passkeys/register")) {
      return "register";
    }
    if (uri.startsWith("/api/v1/rp/passkeys/authenticate")) {
      return "authenticate";
    }
    if (uri.startsWith("/api/v1/admin/auth/login")) {
      return "admin-login";
    }
    return "default";
  }
}
