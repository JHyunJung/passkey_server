package com.crosscert.passkey.auth.apikey.security;

import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService.ResolvedKey;
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
      try {
        chain.doFilter(req, res);
      } finally {
        SecurityContextHolder.clearContext();
      }
      return;
    }

    // Path B: production. Require X-API-Key.
    String header = req.getHeader(HEADER);
    if (header == null || header.isBlank()) {
      chain.doFilter(req, res);
      return;
    }

    Optional<ApiKeyService.ResolvedKey> resolved = apiKeyService.verify(header.trim());
    if (resolved.isEmpty()) {
      chain.doFilter(req, res);
      return;
    }

    Optional<TenantContext> tenantOpt =
        tenantQueryService.findActive(resolved.get().tenantId().toString());
    if (tenantOpt.isEmpty()) {
      chain.doFilter(req, res);
      return;
    }

    TenantContext ctx = tenantOpt.get();
    TenantContextHolder.set(ctx);
    MDC.put("tenantId", ctx.tenantId().toString());
    SecurityContextHolder.getContext()
        .setAuthentication(new ApiKeyAuthenticationToken(resolved.get(), ctx));
    try {
      chain.doFilter(req, res);
    } finally {
      TenantContextHolder.clear();
      MDC.remove("tenantId");
      SecurityContextHolder.clearContext();
    }
  }
}
