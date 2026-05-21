package com.crosscert.passkey.slice.admin;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.controller.AdminPlatformStatsController;
import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.admin.service.AdminPlatformStatsService;
import com.crosscert.passkey.common.exception.GlobalExceptionHandler;
import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.crosscert.passkey.ratelimit.RateLimitFilter;
import com.crosscert.passkey.ratelimit.RateLimitProperties;
import com.crosscert.passkey.ratelimit.RateLimiter;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Slice test for {@link AdminPlatformStatsController}. Verifies that the PLATFORM_OPERATOR guard
 * fires before the cross-tenant aggregate is computed, and that a PLATFORM_OPERATOR receives the
 * platform-wide stats payload.
 */
@WebMvcTest(
    controllers = AdminPlatformStatsController.class,
    properties = "passkey.admin.enabled=true",
    excludeAutoConfiguration = {
      org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
      org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
    })
@Import({
  GlobalExceptionHandler.class,
  TraceIdFilter.class,
  AdminPlatformStatsControllerSliceTest.TestBeans.class,
})
class AdminPlatformStatsControllerSliceTest {

  @Autowired MockMvc mvc;

  @MockBean AdminPlatformStatsService statsService;

  @BeforeEach
  void stubService() {
    when(statsService.compute()).thenReturn(new AdminPlatformStatsService.PlatformStats(10, 3, 42));
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void stats_requires_platform_operator() throws Exception {
    loginAs(AdminRole.RP_ADMIN, UUID.randomUUID());

    mvc.perform(get("/api/v1/admin/platform/stats"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));
  }

  @Test
  void stats_returns_aggregate_for_platform_operator() throws Exception {
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    mvc.perform(get("/api/v1/admin/platform/stats"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.activeCredentials").value(10))
        .andExpect(jsonPath("$.data.activeApiKeys").value(3))
        .andExpect(jsonPath("$.data.ceremonies24h").value(42));
  }

  private static void loginAs(AdminRole role, UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, role, "ops@local", "Ops");
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities()));
  }

  static class TestBeans {
    @Bean
    RateLimitProperties rateLimitProperties() {
      return new RateLimitProperties(true, 30, 60, 120, 5, 10);
    }

    @Bean
    RateLimiter rateLimiter() {
      RateLimiter limiter = Mockito.mock(RateLimiter.class);
      Mockito.when(limiter.tryAcquire(Mockito.anyString(), Mockito.anyInt())).thenReturn(true);
      return limiter;
    }

    @Bean
    RateLimitFilter rateLimitFilter(RateLimitProperties props, RateLimiter limiter) {
      return new RateLimitFilter(props, limiter);
    }
  }
}
