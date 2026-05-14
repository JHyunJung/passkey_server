package com.crosscert.passkey.infrastructure.web;

import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.crosscert.passkey.ratelimit.RateLimitFilter;
import com.crosscert.passkey.ratelimit.RateLimitProperties;
import com.crosscert.passkey.ratelimit.RateLimiter;
import com.crosscert.passkey.tenant.resolver.TenantResolutionFilter;
import com.crosscert.passkey.tenant.resolver.TenantResolver;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Pins the order of HTTP filters explicitly.
 *
 * <pre>
 *   HIGHEST_PRECEDENCE      → TraceIdFilter          (MDC traceId set first)
 *   HIGHEST_PRECEDENCE + 10 → TenantResolutionFilter (depends on traceId for logs)
 *   (M3) Security filter chain follows.
 * </pre>
 *
 * Filters are not {@code @Component}-stereotyped, so this config is the sole place that registers
 * them on the servlet chain. Each is wrapped in {@link FilterRegistrationBean} with an explicit
 * order — Spring Boot's auto-detection rules don't override.
 */
@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class WebFilterConfig {

  @Bean
  public TraceIdFilter traceIdFilter() {
    return new TraceIdFilter();
  }

  @Bean
  public TenantResolutionFilter tenantResolutionFilter(List<TenantResolver> resolvers) {
    return new TenantResolutionFilter(resolvers);
  }

  @Bean
  public FilterRegistrationBean<TraceIdFilter> traceIdFilterRegistration(TraceIdFilter filter) {
    FilterRegistrationBean<TraceIdFilter> bean = new FilterRegistrationBean<>(filter);
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    bean.addUrlPatterns("/*");
    return bean;
  }

  @Bean
  public FilterRegistrationBean<TenantResolutionFilter> tenantResolutionFilterRegistration(
      TenantResolutionFilter filter) {
    FilterRegistrationBean<TenantResolutionFilter> bean = new FilterRegistrationBean<>(filter);
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
    bean.addUrlPatterns("/*");
    return bean;
  }

  @Bean
  public RateLimitFilter rateLimitFilter(RateLimitProperties props, RateLimiter limiter) {
    return new RateLimitFilter(props, limiter);
  }

  @Bean
  public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(
      RateLimitFilter filter) {
    FilterRegistrationBean<RateLimitFilter> bean = new FilterRegistrationBean<>(filter);
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
    bean.addUrlPatterns("/api/*");
    return bean;
  }
}
