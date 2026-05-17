package com.crosscert.passkey.unit.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.admin.security.AdminSecurityConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Verifies the admin CORS bean produced by {@link AdminSecurityConfig} matches what the cross-site
 * admin console SPA needs: explicit origin allow-list, credentials enabled, CSRF + Content-Type
 * headers permitted. The bean is built reflectively here so we don't need to spin up the full
 * Spring context for a focused contract test.
 */
class AdminCorsConfigTest {

  @Test
  void cors_config_allows_admin_console_origin_with_credentials_and_csrf_header() throws Exception {
    AdminSecurityConfig config = new AdminSecurityConfig(new ObjectMapper());
    setField(config, "adminConsoleOrigin", "https://admin.passkey.example.com");
    setField(config, "cookieSecure", true);
    setField(config, "cookieSameSite", "None");

    CorsConfigurationSource source = invokeCorsSource(config);

    HttpServletRequest req = new MockHttpServletRequest("OPTIONS", "/api/v1/admin/auth/login");
    CorsConfiguration cfg = source.getCorsConfiguration(req);
    assertThat(cfg).isNotNull();
    assertThat(cfg.getAllowedOrigins()).containsExactly("https://admin.passkey.example.com");
    assertThat(cfg.getAllowCredentials()).isTrue();
    assertThat(cfg.getAllowedMethods()).contains("GET", "POST", "PUT", "DELETE", "OPTIONS");
    assertThat(cfg.getAllowedHeaders()).contains("Content-Type", "X-XSRF-TOKEN");
  }

  private static void setField(Object target, String name, Object value) throws Exception {
    Field f = AdminSecurityConfig.class.getDeclaredField(name);
    f.setAccessible(true);
    f.set(target, value);
  }

  private static CorsConfigurationSource invokeCorsSource(AdminSecurityConfig config)
      throws Exception {
    Method m = AdminSecurityConfig.class.getDeclaredMethod("corsConfigurationSource");
    m.setAccessible(true);
    return (CorsConfigurationSource) m.invoke(config);
  }
}
