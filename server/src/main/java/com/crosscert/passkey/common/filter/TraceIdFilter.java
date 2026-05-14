package com.crosscert.passkey.common.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Registered as a single bean by {@code WebFilterConfig} via {@code FilterRegistrationBean}, which
 * pins the filter order. Intentionally NOT a {@code @Component} — Spring Boot's {@code
 * FilterAndOrderResolver} auto-registers component-scanned Filters as well, which would
 * double-register the chain and re-run logic that re-generates the traceId on the second pass.
 */
public class TraceIdFilter extends OncePerRequestFilter {

  public static final String TRACE_ID_HEADER = "X-Trace-Id";
  public static final String MDC_KEY = "traceId";

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    String traceId =
        Optional.ofNullable(req.getHeader(TRACE_ID_HEADER))
            .filter(s -> !s.isBlank())
            .orElseGet(() -> UUID.randomUUID().toString().replace("-", "").substring(0, 16));

    MDC.put(MDC_KEY, traceId);
    res.setHeader(TRACE_ID_HEADER, traceId);

    try {
      chain.doFilter(req, res);
    } finally {
      MDC.remove(MDC_KEY);
    }
  }
}
