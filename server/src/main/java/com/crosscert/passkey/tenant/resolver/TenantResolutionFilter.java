package com.crosscert.passkey.tenant.resolver;

import com.crosscert.passkey.tenant.context.TenantContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Walks each registered {@link TenantResolver} in order; first non-empty result wins. Stores the
 * context in {@link TenantContextHolder} and clears it in a {@code finally} to prevent leakage
 * across pooled threads.
 *
 * <p>Registered as a single bean by {@code WebFilterConfig} via {@code FilterRegistrationBean};
 * intentionally not a {@code @Component} to avoid double-registration on the servlet filter chain.
 */
@RequiredArgsConstructor
public class TenantResolutionFilter extends OncePerRequestFilter {

  public static final String MDC_KEY = "tenantId";

  private final List<TenantResolver> resolvers;

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    try {
      resolvers.stream()
          .map(r -> r.resolve(req))
          .filter(opt -> opt.isPresent())
          .map(opt -> opt.get())
          .findFirst()
          .ifPresent(
              ctx -> {
                TenantContextHolder.set(ctx);
                MDC.put(MDC_KEY, ctx.tenantId().toString());
              });
      chain.doFilter(req, res);
    } finally {
      TenantContextHolder.clear();
      MDC.remove(MDC_KEY);
    }
  }
}
