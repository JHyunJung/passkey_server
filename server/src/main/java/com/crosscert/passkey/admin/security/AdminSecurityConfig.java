package com.crosscert.passkey.admin.security;

import com.crosscert.passkey.admin.repository.AdminUserRepository;
import com.crosscert.passkey.auth.apikey.security.ApiKeyAuthenticationFilter;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.tenant.service.TenantQueryService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Three security chains:
 *
 * <ol>
 *   <li>Order(1) — {@code /api/v1/admin/**}: form login + session cookie + CSRF token.
 *   <li>Order(2) — {@code /api/v1/rp/**}: stateless, API key resolution handled by {@code
 *       ApiKeyTenantResolver}/{@code TenantResolutionFilter}; Spring Security stays out of the way
 *       (permit-all because the tenant filter already enforces the gate).
 *   <li>Order(3) — everything else (actuator, /_diag, swagger, error): permitAll.
 * </ol>
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class AdminSecurityConfig {

  private final ObjectMapper objectMapper;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @Order(1)
  public SecurityFilterChain adminFilterChain(HttpSecurity http, AdminUserRepository adminRepo)
      throws Exception {
    return http.securityMatcher("/api/v1/admin/**")
        .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
        .authorizeHttpRequests(
            authz ->
                authz
                    .requestMatchers("/api/v1/admin/auth/login")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .formLogin(
            form ->
                form.loginProcessingUrl("/api/v1/admin/auth/login")
                    .successHandler(new AdminAuthenticationSuccessHandler(adminRepo))
                    .failureHandler(
                        (req, res, ex) -> {
                          log.warn(
                              "admin.login.failure email={} ip={} reason={}",
                              sanitiseEmail(req.getParameter("username")),
                              req.getRemoteAddr(),
                              ex.getClass().getSimpleName());
                          writeError(res, HttpStatus.UNAUTHORIZED, "A001", "Login failed");
                        }))
        .logout(
            logout ->
                logout
                    .logoutUrl("/api/v1/admin/auth/logout")
                    .logoutRequestMatcher(
                        new AntPathRequestMatcher("/api/v1/admin/auth/logout", "POST"))
                    .logoutSuccessHandler(
                        (req, res, auth) -> writeJson(res, HttpStatus.OK, "Logged out")))
        .exceptionHandling(
            ex ->
                ex.authenticationEntryPoint(
                        (req, res, e) -> {
                          log.warn(
                              "admin.unauthenticated path={} ip={}",
                              req.getRequestURI(),
                              req.getRemoteAddr());
                          writeError(res, HttpStatus.UNAUTHORIZED, "A010", "Admin login required");
                        })
                    .accessDeniedHandler(
                        (req, res, e) -> {
                          log.warn(
                              "admin.access_denied path={} ip={} reason={}",
                              req.getRequestURI(),
                              req.getRemoteAddr(),
                              e.getMessage());
                          writeError(res, HttpStatus.FORBIDDEN, "A002", "Access denied");
                        }))
        .addFilterBefore(
            new com.crosscert.passkey.admin.security.JsonLoginAuthenticationFilter(objectMapper),
            UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(new AdminMdcFilter(), UsernamePasswordAuthenticationFilter.class)
        .build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain rpFilterChain(
      HttpSecurity http, ApiKeyService apiKeyService, TenantQueryService tenantQueryService)
      throws Exception {
    return http.securityMatcher("/api/v1/rp/**")
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(
            new ApiKeyAuthenticationFilter(apiKeyService, tenantQueryService),
            UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
        .exceptionHandling(
            ex ->
                ex.authenticationEntryPoint(
                    (req, res, e) -> {
                      log.warn(
                          "rp.unauthorized path={} ip={}",
                          req.getRequestURI(),
                          req.getRemoteAddr());
                      writeError(
                          res, HttpStatus.UNAUTHORIZED, "A005", "Invalid or missing API key");
                    }))
        .build();
  }

  @Bean
  @Order(3)
  public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception {
    // Only health probes + info + diag + swagger are public. Prometheus, env, beans, etc. fall
    // through to actuatorChain (Order 4) which requires basic auth or is reachable only from the
    // private network in production (LB / k8s NetworkPolicy).
    return http.securityMatcher(
            "/actuator/health/**",
            "/actuator/info",
            "/_diag/**",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/error")
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
        .build();
  }

  @Bean
  @Order(4)
  public SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
    // Sensitive actuator endpoints — /actuator/prometheus, /actuator/env, etc. — require
    // authentication. HTTP basic against the in-memory actuator user. Production should
    // additionally
    // restrict access at the network layer (LB rule / k8s NetworkPolicy).
    return http.securityMatcher("/actuator/**")
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .httpBasic(org.springframework.security.config.Customizer.withDefaults())
        .authorizeHttpRequests(authz -> authz.anyRequest().hasRole("ACTUATOR"))
        .build();
  }

  private void writeJson(HttpServletResponse res, HttpStatus status, String msg)
      throws java.io.IOException {
    res.setStatus(status.value());
    res.setContentType("application/json");
    res.getWriter().write(objectMapper.writeValueAsString(ApiResponse.ok(msg, null)));
  }

  /**
   * Masks the local-part of an email for safer logging — keeps domain visible for grouping by
   * tenant/RP while not exposing full PII in operational logs.
   */
  private String sanitiseEmail(String email) {
    if (email == null || email.isBlank()) {
      return "-";
    }
    String stripped = email.replace('\n', '_').replace('\r', '_');
    int at = stripped.indexOf('@');
    if (at <= 1) {
      return "***" + stripped.substring(Math.max(0, at));
    }
    return stripped.charAt(0) + "***" + stripped.substring(at);
  }

  private void writeError(HttpServletResponse res, HttpStatus status, String code, String msg)
      throws java.io.IOException {
    res.setStatus(status.value());
    res.setContentType("application/json");
    String body =
        "{\"success\":false,\"code\":\""
            + code
            + "\",\"message\":\""
            + msg
            + "\",\"error\":{\"errorCode\":\""
            + code
            + "\"}}";
    res.getWriter().write(body);
  }
}
