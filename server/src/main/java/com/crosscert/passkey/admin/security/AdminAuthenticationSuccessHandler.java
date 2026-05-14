package com.crosscert.passkey.admin.security;

import com.crosscert.passkey.admin.domain.AdminUser;
import com.crosscert.passkey.admin.repository.AdminUserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.transaction.annotation.Transactional;

/**
 * Replaces the post-login {@code Authentication} with one whose principal is an {@link
 * AdminPrincipal} carrying tenantId + role. Also records login time.
 */
@RequiredArgsConstructor
public class AdminAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private final AdminUserRepository repo;

  @Override
  @Transactional
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication auth)
      throws IOException, ServletException {
    String email = auth.getName();
    AdminUser admin =
        repo.findByEmail(email)
            .orElseThrow(() -> new IllegalStateException("admin lost: " + email));
    admin.recordLogin();

    AdminPrincipal principal =
        new AdminPrincipal(
            admin.getId(),
            admin.getTenantId(),
            admin.getRole(),
            admin.getEmail(),
            admin.getDisplayName());
    Authentication enriched =
        new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(enriched);

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    response
        .getWriter()
        .write(
            "{\"success\":true,\"code\":\"OK\",\"message\":\"Login successful\",\"data\":{\"adminId\":\""
                + admin.getId()
                + "\",\"role\":\""
                + admin.getRole()
                + "\"}}");
  }
}
