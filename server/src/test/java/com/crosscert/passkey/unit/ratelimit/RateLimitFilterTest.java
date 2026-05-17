package com.crosscert.passkey.unit.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.ratelimit.RateLimitFilter;
import com.crosscert.passkey.ratelimit.RateLimitProperties;
import com.crosscert.passkey.ratelimit.RateLimiter;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

  private static final UUID TENANT_ID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

  @Mock private RateLimiter limiter;
  @Mock private FilterChain chain;

  private final RateLimitProperties props = new RateLimitProperties(true, 30, 60, 120, 5, 10);
  private RateLimitFilter filter;

  @BeforeEach
  void setUp() {
    // Defend against thread-local leakage from sibling tests — JUnit reuses the JVM thread and the
    // earlier @AfterEach is not guaranteed to have run if the previous test failed unusually.
    TenantContextHolder.clear();
    filter = new RateLimitFilter(props, limiter);
  }

  @AfterEach
  void clearContext() {
    TenantContextHolder.clear();
  }

  @Test
  void register_path_uses_registration_limit_and_tenant_bucket() throws Exception {
    TenantContextHolder.set(new TenantContext(TENANT_ID, "test"));
    when(limiter.tryAcquire(anyString(), anyInt())).thenReturn(true);
    MockHttpServletRequest req = mockRequest("/api/v1/rp/passkeys/register/options");

    filter.doFilter(req, new MockHttpServletResponse(), chain);

    ArgumentCaptor<String> bucket = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Integer> limit = ArgumentCaptor.forClass(Integer.class);
    verify(limiter).tryAcquire(bucket.capture(), limit.capture());
    assertThat(limit.getValue()).isEqualTo(30);
    assertThat(bucket.getValue()).isEqualTo(TENANT_ID + ":register");
    verify(chain, times(1))
        .doFilter(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
  }

  @Test
  void admin_login_uses_ip_bucket_even_without_tenant_context() throws Exception {
    when(limiter.tryAcquire(anyString(), anyInt())).thenReturn(true);
    MockHttpServletRequest req = mockRequest("/api/v1/admin/auth/login");
    req.setRemoteAddr("203.0.113.7");

    filter.doFilter(req, new MockHttpServletResponse(), chain);

    ArgumentCaptor<String> bucket = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Integer> limit = ArgumentCaptor.forClass(Integer.class);
    verify(limiter).tryAcquire(bucket.capture(), limit.capture());
    assertThat(limit.getValue()).isEqualTo(5);
    assertThat(bucket.getValue()).isEqualTo("ip:203.0.113.7:admin-login");
  }

  @Test
  void unknown_path_falls_back_to_default_limit_and_anon_bucket() throws Exception {
    when(limiter.tryAcquire(anyString(), anyInt())).thenReturn(true);
    MockHttpServletRequest req = mockRequest("/api/v1/rp/credentials");
    req.setRemoteAddr("198.51.100.1");

    filter.doFilter(req, new MockHttpServletResponse(), chain);

    ArgumentCaptor<String> bucket = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Integer> limit = ArgumentCaptor.forClass(Integer.class);
    verify(limiter).tryAcquire(bucket.capture(), limit.capture());
    assertThat(limit.getValue()).isEqualTo(120);
    assertThat(bucket.getValue()).isEqualTo("anon:198.51.100.1:default");
  }

  @Test
  void exceeded_limit_throws_business_exception_and_skips_chain() {
    TenantContextHolder.set(new TenantContext(TENANT_ID, "test"));
    when(limiter.tryAcquire(anyString(), anyInt())).thenReturn(false);
    MockHttpServletRequest req = mockRequest("/api/v1/rp/passkeys/authenticate/options");
    HttpServletResponse res = new MockHttpServletResponse();

    BusinessException ex =
        org.junit.jupiter.api.Assertions.assertThrows(
            BusinessException.class, () -> filter.doFilter(req, res, chain));
    assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMIT_EXCEEDED);
  }

  @Test
  void actuator_and_diag_paths_skip_limiter() throws Exception {
    filter.doFilter(mockRequest("/actuator/health"), new MockHttpServletResponse(), chain);
    filter.doFilter(mockRequest("/_diag/info"), new MockHttpServletResponse(), chain);
    verify(limiter, never()).tryAcquire(anyString(), anyInt());
  }

  @Test
  void disabled_filter_skips_limiter() throws Exception {
    RateLimitProperties disabled = new RateLimitProperties(false, 30, 60, 120, 5, 10);
    RateLimitFilter f = new RateLimitFilter(disabled, limiter);
    MockHttpServletRequest req = mockRequest("/api/v1/rp/passkeys/register/options");

    f.doFilter(req, new MockHttpServletResponse(), chain);
    verify(limiter, never()).tryAcquire(anyString(), anyInt());
  }

  @Test
  void authentication_path_uses_authentication_limit() throws Exception {
    TenantContextHolder.set(new TenantContext(TENANT_ID, "test"));
    when(limiter.tryAcquire(anyString(), anyInt())).thenReturn(true);
    MockHttpServletRequest req = mockRequest("/api/v1/rp/passkeys/authenticate/verify");

    filter.doFilter(req, new MockHttpServletResponse(), chain);

    verify(limiter, times(1)).tryAcquire(TENANT_ID + ":authenticate", 60);
  }

  private MockHttpServletRequest mockRequest(String uri) {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI(uri);
    return req;
  }
}
