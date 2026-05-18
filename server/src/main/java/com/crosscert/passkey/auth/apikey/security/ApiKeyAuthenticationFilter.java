package com.crosscert.passkey.auth.apikey.security;

import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService.ResolvedKey;
import com.crosscert.passkey.common.log.LogSanitiser;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.service.TenantQueryService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the RP from {@code X-API-Key} and establishes both the Spring Security {@code
 * Authentication} and the {@link TenantContextHolder}. Missing/invalid keys yield an empty
 * SecurityContext so the chain's {@code .authenticated()} rule rejects the request with 401.
 *
 * <p>If the {@code TenantResolutionFilter} already set a {@link TenantContext} (e.g. via the {@code
 * X-Tenant-Id} header in dev profile), this filter picks it up and creates the Authentication
 * without re-running Argon2 verify — allowing slice/integration tests to bypass the API key flow
 * without losing the 401 contract in production.
 */
@Slf4j
@RequiredArgsConstructor
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

  public static final String HEADER = "X-API-Key";

  private final ApiKeyService apiKeyService;
  private final TenantQueryService tenantQueryService;

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {

    // Path A: dev/test profile may already have populated TenantContext via the header resolver.
    Optional<TenantContext> preExisting = TenantContextHolder.optional();
    if (preExisting.isPresent()) {
      ResolvedKey dummy = new ResolvedKey(preExisting.get().tenantId(), UUID.randomUUID());
      SecurityContextHolder.getContext()
          .setAuthentication(new ApiKeyAuthenticationToken(dummy, preExisting.get()));
      MDC.put("apiKeyId", dummy.apiKeyId().toString());
      try {
        chain.doFilter(req, res);
      } finally {
        MDC.remove("apiKeyId");
        SecurityContextHolder.clearContext();
      }
      return;
    }

    // Path B: production. Require X-API-Key. Each rejection path logs a distinct event name so
    // ops can grep "apikey.auth.reject" and split by reason — missing header is a normal 401 for
    // mis-wired clients, verify_failed is a brute-force / leaked-key signal worth alerting on,
    // and tenant_inactive points at admin action that left a stale key.
    String header = req.getHeader(HEADER);
    if (header == null || header.isBlank()) {
      log.debug(
          "apikey.auth.reject reason=missing_header path={} ip={}",
          LogSanitiser.forLog(req.getRequestURI()),
          req.getRemoteAddr());
      chain.doFilter(req, res);
      return;
    }

    String presented = header.trim();
    String prefix = extractPrefixForLog(presented);
    Optional<ApiKeyService.ResolvedKey> resolved = apiKeyService.verify(presented);
    if (resolved.isEmpty()) {
      log.warn(
          "apikey.auth.reject reason=verify_failed prefix={} path={} ip={}",
          prefix,
          LogSanitiser.forLog(req.getRequestURI()),
          req.getRemoteAddr());
      chain.doFilter(req, res);
      return;
    }

    Optional<TenantContext> tenantOpt =
        tenantQueryService.findActive(resolved.get().tenantId().toString());
    if (tenantOpt.isEmpty()) {
      // Valid signature but the tenant row is missing or not ACTIVE — likely an operator paused
      // the tenant while a client still holds a working key. Treat as WARN so it surfaces in
      // dashboards but does not page (no security implication; the request still 401s).
      log.warn(
          "apikey.auth.reject reason=tenant_inactive prefix={} apiKeyId={} tenantId={} path={}",
          prefix,
          resolved.get().apiKeyId(),
          resolved.get().tenantId(),
          LogSanitiser.forLog(req.getRequestURI()));
      chain.doFilter(req, res);
      return;
    }

    TenantContext ctx = tenantOpt.get();
    TenantContextHolder.set(ctx);
    MDC.put("tenantId", ctx.tenantId().toString());
    MDC.put("apiKeyId", resolved.get().apiKeyId().toString());
    SecurityContextHolder.getContext()
        .setAuthentication(new ApiKeyAuthenticationToken(resolved.get(), ctx));
    // Success at TRACE — every authenticated request would otherwise double the log volume.
    if (log.isTraceEnabled()) {
      log.trace(
          "apikey.auth.accept prefix={} apiKeyId={} tenantId={}",
          prefix,
          resolved.get().apiKeyId(),
          ctx.tenantId());
    }
    try {
      chain.doFilter(req, res);
    } finally {
      TenantContextHolder.clear();
      MDC.remove("tenantId");
      MDC.remove("apiKeyId");
      SecurityContextHolder.clearContext();
    }
  }

  /**
   * Pulls the prefix portion (the public, non-secret half) out of a presented key for forensic
   * logging. Returns "-" when the header is malformed so we still get a comparable column.
   */
  private static String extractPrefixForLog(String presented) {
    if (presented == null) {
      return "-";
    }
    int underscore = presented.indexOf('_');
    int dot = presented.indexOf('.');
    if (underscore < 0 || dot < 0 || dot < underscore) {
      return "malformed";
    }
    return LogSanitiser.forLog(presented.substring(underscore + 1, dot));
  }
}
