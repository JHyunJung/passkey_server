package com.crosscert.passkey.admin.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Populates the {@code adminId} MDC key from the {@link AdminPrincipal} in the current
 * SecurityContext, so every log line inside an admin request carries the admin identity. Cleared in
 * {@code finally} to prevent leakage across pooled threads.
 */
public class AdminMdcFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean putMdc = false;
    if (auth != null && auth.getPrincipal() instanceof AdminPrincipal principal) {
      MDC.put("adminId", principal.adminId().toString());
      if (principal.tenantId() != null) {
        MDC.put("tenantId", principal.tenantId().toString());
      }
      putMdc = true;
    }
    try {
      chain.doFilter(req, res);
    } finally {
      if (putMdc) {
        MDC.remove("adminId");
        MDC.remove("tenantId");
      }
    }
  }
}
