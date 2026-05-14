package com.crosscert.passkey.admin.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Pre-filter that converts a JSON {@code {email,password}} body on {@code POST
 * /api/v1/admin/auth/login} into request parameters {@code username}+{@code password} expected by
 * Spring Security's {@code UsernamePasswordAuthenticationFilter}.
 */
public class JsonLoginAuthenticationFilter extends OncePerRequestFilter {

  private final ObjectMapper objectMapper;

  public JsonLoginAuthenticationFilter(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !("POST".equalsIgnoreCase(request.getMethod())
        && "/api/v1/admin/auth/login".equals(request.getRequestURI())
        && request.getContentType() != null
        && request.getContentType().toLowerCase().contains(MediaType.APPLICATION_JSON_VALUE));
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    byte[] body = req.getInputStream().readAllBytes();
    LoginBody payload = objectMapper.readValue(body, LoginBody.class);
    HttpServletRequest wrapper =
        new jakarta.servlet.http.HttpServletRequestWrapper(req) {
          @Override
          public String getParameter(String name) {
            if ("username".equals(name)) return payload.email();
            if ("password".equals(name)) return payload.password();
            return super.getParameter(name);
          }
        };
    chain.doFilter(wrapper, res);
  }

  record LoginBody(String email, String password) {
    LoginBody {
      if (email == null) email = "";
      if (password == null) password = "";
    }
  }

  // Keep StandardCharsets referenced so the helper retains its purpose if reused later.
  @SuppressWarnings("unused")
  private static final java.nio.charset.Charset UTF8 = StandardCharsets.UTF_8;
}
