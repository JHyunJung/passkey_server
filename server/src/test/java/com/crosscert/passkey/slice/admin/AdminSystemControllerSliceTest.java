package com.crosscert.passkey.slice.admin;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.controller.AdminSystemController;
import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.common.exception.GlobalExceptionHandler;
import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.crosscert.passkey.credential.metadata.MdsProperties;
import com.crosscert.passkey.ratelimit.RateLimitFilter;
import com.crosscert.passkey.ratelimit.RateLimitProperties;
import com.crosscert.passkey.ratelimit.RateLimiter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Slice test for {@link AdminSystemController}. Verifies that the PLATFORM_OPERATOR guard fires
 * before any system action, that the MDS status passthrough reports DISABLED when no provider bean
 * is wired, and that the rate-limit snapshot serialises correctly.
 */
@WebMvcTest(
    controllers = AdminSystemController.class,
    excludeAutoConfiguration = {
      org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
      org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
    })
@Import({
  GlobalExceptionHandler.class,
  TraceIdFilter.class,
  AdminSystemControllerSliceTest.TestBeans.class,
})
class AdminSystemControllerSliceTest {

  @Autowired MockMvc mvc;

  // No MdsBlobProvider bean is registered in this slice; the ObjectProvider Spring autowires into
  // the controller therefore reports getIfAvailable()=null, which is exactly the path we want to
  // assert against (status=DISABLED, refresh→P014).

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void mds_status_requires_platform_operator() throws Exception {
    loginAs(AdminRole.RP_ADMIN, UUID.randomUUID());

    mvc.perform(get("/api/v1/admin/system/mds/status"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));
  }

  @Test
  void mds_status_returns_disabled_payload_when_provider_missing() throws Exception {
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    mvc.perform(get("/api/v1/admin/system/mds/status"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.status").value("DISABLED"));
  }

  @Test
  void mds_refresh_rejected_when_disabled() throws Exception {
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    mvc.perform(post("/api/v1/admin/system/mds/refresh"))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("P014"));
  }

  @Test
  void rate_limit_endpoint_returns_snapshot_for_platform_operator() throws Exception {
    loginAs(AdminRole.PLATFORM_OPERATOR, null);

    mvc.perform(get("/api/v1/admin/system/rate-limit"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.limits.REGISTER").exists())
        .andExpect(jsonPath("$.data.limits.AUTHENTICATE").exists())
        .andExpect(jsonPath("$.data.denyCount").exists());
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
    @Primary
    MdsProperties mdsProperties() {
      MdsProperties p = new MdsProperties();
      p.setEnabled(false);
      return p;
    }

    @Bean
    SimpleMeterRegistry meterRegistry() {
      return new SimpleMeterRegistry();
    }

    @Bean
    RateLimitProperties rateLimitProperties() {
      return new RateLimitProperties(true, 30, 60, 120, 5, 10);
    }

    @Bean
    RateLimiter rateLimiter() {
      // unused by AdminSystemController but needed because RateLimitFilter constructor demands
      // it. Stub tryAcquire(...)=true so the filter doesn't reject every test request.
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
