package com.crosscert.passkey.admin.security;

import com.crosscert.passkey.admin.repository.AdminUserRepository;
import com.crosscert.passkey.auth.apikey.security.ApiKeyAuthenticationFilter;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.log.LogSanitiser;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.tenant.service.TenantQueryService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Four security chains:
 *
 * <ol>
 *   <li>Order(1) — {@code /api/v1/admin/**}: form login + session cookie + CSRF token (cookie
 *       attributes: {@code Secure}, {@code SameSite=Lax}, {@code Path=/api/v1/admin}; HttpOnly is
 *       intentionally off so the SPA reads the token and echoes it in the {@code X-XSRF-TOKEN}
 *       header).
 *   <li>Order(2) — {@code /api/v1/rp/**}: stateless, API key resolution via {@link
 *       ApiKeyAuthenticationFilter}.
 *   <li>Order(3) — health/info, {@code /_diag}, swagger, error: permitAll.
 *   <li>Order(4) — remaining {@code /actuator/**}: HTTP basic + {@code ROLE_ACTUATOR}.
 * </ol>
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class AdminSecurityConfig {

  private final ObjectMapper objectMapper;

  /**
   * Controls the {@code Secure} flag on the CSRF and session cookies. Defaults to true so prod is
   * locked down by default; local HTTP-only development overrides to false.
   */
  @Value("${passkey.cookie.secure:true}")
  private boolean cookieSecure;

  /**
   * Cookie {@code SameSite} attribute for CSRF and session cookies. {@code lax} is the local /
   * same-origin default. {@code none} is required when the admin console is hosted on a separate
   * cross-site origin (e.g. {@code admin.passkey.example.com}); it must be paired with {@code
   * Secure=true} and an allow-listed CORS origin.
   */
  @Value("${passkey.cookie.same-site:Lax}")
  private String cookieSameSite;

  /**
   * Allowed origin for cross-origin admin console traffic. When blank, CORS is disabled (same-
   * origin only — local development). Configure via {@code PASSKEY_ADMIN_CONSOLE_ORIGIN} in prod.
   */
  @Value("${passkey.admin.console-origin:}")
  private String adminConsoleOrigin;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @Order(1)
  public SecurityFilterChain adminFilterChain(
      HttpSecurity http,
      AdminUserRepository adminRepo,
      AdminUserDetailsService adminUserDetailsService)
      throws Exception {
    // Two UserDetailsService beans (admin + actuator) coexist, so Spring's autoconfiguration skips
    // wiring a global DaoAuthenticationProvider. Bind ours explicitly to the admin chain.
    DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
    daoProvider.setUserDetailsService(adminUserDetailsService);
    daoProvider.setPasswordEncoder(passwordEncoder());
    CookieCsrfTokenRepository csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
    // SPA reads XSRF-TOKEN via document.cookie which honours Path scope — anchor the cookie at "/"
    // so the SPA's router pages (and axios in particular) can read it before any /api/v1/admin
    // request goes out. SameSite=Lax + Path=/ is fine because we still gate the API itself.
    String csrfPath = "/";
    csrfRepo.setCookieCustomizer(
        cookie -> cookie.secure(cookieSecure).sameSite(cookieSameSite).path(csrfPath));
    // Force eager CSRF token resolution so the XSRF-TOKEN cookie is set on the very first response,
    // letting the SPA echo it in X-XSRF-TOKEN on the next login POST. Without this, Spring Security
    // 6's deferred handler skips setting the cookie when no request attribute reads the token.
    CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
    csrfHandler.setCsrfRequestAttributeName(null);
    return http.securityMatcher("/api/v1/admin/**")
        .authenticationProvider(daoProvider)
        .cors(
            c -> {
              if (adminConsoleOrigin != null && !adminConsoleOrigin.isBlank()) {
                c.configurationSource(corsConfigurationSource());
              } else {
                c.disable();
              }
            })
        .csrf(c -> c.csrfTokenRepository(csrfRepo).csrfTokenRequestHandler(csrfHandler))
        .headers(adminHeaders())
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
                              LogSanitiser.maskEmail(req.getParameter("username")),
                              req.getRemoteAddr(),
                              ex.getClass().getSimpleName());
                          writeError(res, ErrorCode.UNAUTHORIZED);
                        }))
        .logout(
            logout ->
                logout
                    .logoutUrl("/api/v1/admin/auth/logout")
                    .logoutRequestMatcher(
                        PathPatternRequestMatcher.withDefaults()
                            .matcher(
                                org.springframework.http.HttpMethod.POST,
                                "/api/v1/admin/auth/logout"))
                    .logoutSuccessHandler(
                        (req, res, auth) -> writeJson(res, HttpStatus.OK, "Logged out")))
        .exceptionHandling(
            ex ->
                ex.authenticationEntryPoint(
                        (req, res, e) -> {
                          log.warn(
                              "admin.unauthenticated path={} ip={}",
                              LogSanitiser.forLog(req.getRequestURI()),
                              req.getRemoteAddr());
                          writeError(res, ErrorCode.ADMIN_LOGIN_REQUIRED);
                        })
                    .accessDeniedHandler(
                        (req, res, e) -> {
                          log.warn(
                              "admin.access_denied path={} ip={} reason={}",
                              LogSanitiser.forLog(req.getRequestURI()),
                              req.getRemoteAddr(),
                              LogSanitiser.forLog(e.getMessage()));
                          writeError(res, ErrorCode.ACCESS_DENIED);
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
        .headers(apiHeaders())
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
                          LogSanitiser.forLog(req.getRequestURI()),
                          req.getRemoteAddr());
                      writeError(res, ErrorCode.INVALID_API_KEY);
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
        // Health/info/error are JSON; Swagger needs to render HTML+inline script, so keep CSP off
        // here but still apply HSTS + frame-ancestors via apiHeaders without contentSecurityPolicy.
        .headers(
            h ->
                h.httpStrictTransportSecurity(
                        hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000))
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                    .referrerPolicy(
                        rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
        .build();
  }

  @Bean
  @Order(4)
  public SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
    // Sensitive actuator endpoints — /actuator/prometheus, /actuator/env, etc. — require
    // authentication. HTTP basic against the in-memory actuator user. Production should
    // additionally restrict access at the network layer (LB rule / k8s NetworkPolicy).
    return http.securityMatcher("/actuator/**")
        .csrf(AbstractHttpConfigurer::disable)
        .headers(apiHeaders())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .httpBasic(Customizer.withDefaults())
        .authorizeHttpRequests(authz -> authz.anyRequest().hasRole("ACTUATOR"))
        .build();
  }

  /**
   * CORS source for the admin chain. Used only when {@link #adminConsoleOrigin} is non-blank — the
   * admin console SPA lives on a different origin (e.g. {@code admin.passkey.example.com}) and must
   * send credentials (session cookie + CSRF cookie) cross-site.
   */
  private CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowedOrigins(List.of(adminConsoleOrigin));
    cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    cfg.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN", "X-Trace-Id"));
    cfg.setExposedHeaders(List.of("X-Trace-Id"));
    cfg.setAllowCredentials(true);
    cfg.setMaxAge(Duration.ofHours(1));
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/v1/admin/**", cfg);
    return source;
  }

  /**
   * Headers for HTML-rendering chains (admin console SPA). Same as {@link #apiHeaders()} except
   * {@code frame-ancestors} stays {@code 'none'} (the SPA does not iframe itself) and we leave room
   * for future {@code script-src 'self'} if the admin UI is ever served from the same origin.
   */
  private Customizer<HeadersConfigurer<HttpSecurity>> adminHeaders() {
    return h ->
        h.httpStrictTransportSecurity(
                hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000))
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
            .referrerPolicy(
                rp ->
                    rp.policy(
                        ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
            .contentSecurityPolicy(
                csp ->
                    csp.policyDirectives(
                        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
                            + "form-action 'self'"));
  }

  /**
   * Strictest headers for JSON APIs and actuator endpoints. The body is never rendered as HTML, so
   * CSP can be locked to {@code default-src 'none'}.
   */
  private Customizer<HeadersConfigurer<HttpSecurity>> apiHeaders() {
    return h ->
        h.httpStrictTransportSecurity(
                hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000))
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
            .referrerPolicy(rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            .contentSecurityPolicy(
                csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"));
  }

  private void writeJson(HttpServletResponse res, HttpStatus status, String msg)
      throws java.io.IOException {
    res.setStatus(status.value());
    res.setContentType("application/json");
    res.getWriter().write(objectMapper.writeValueAsString(ApiResponse.ok(msg, null)));
  }

  private void writeError(HttpServletResponse res, ErrorCode code) throws java.io.IOException {
    res.setStatus(code.getStatus().value());
    res.setContentType("application/json");
    res.getWriter().write(objectMapper.writeValueAsString(ApiResponse.error(code)));
  }
}
