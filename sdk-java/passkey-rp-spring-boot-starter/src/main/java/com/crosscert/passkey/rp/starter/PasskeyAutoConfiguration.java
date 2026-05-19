package com.crosscert.passkey.rp.starter;

import com.crosscert.passkey.rp.client.DefaultPasskeyClient;
import com.crosscert.passkey.rp.client.JdkPasskeyHttpClient;
import com.crosscert.passkey.rp.client.MultiTenantPasskeyClient;
import com.crosscert.passkey.rp.client.PasskeyClient;
import com.crosscert.passkey.rp.client.PasskeyHttpClient;
import com.crosscert.passkey.rp.client.RetryPolicy;
import com.crosscert.passkey.rp.jwt.JwtVerifier;
import com.crosscert.passkey.rp.jwt.NimbusJwtVerifier;
import com.crosscert.passkey.rp.jwt.RefreshTokenManager;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import com.crosscert.passkey.rp.tenant.FixedApiKeyResolver;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Wires the SDK into a Spring Boot app. Defaults work out of the box for a single-tenant RP; every
 * bean is replaceable by declaring one of the same type in the host app.
 */
@AutoConfiguration
@EnableConfigurationProperties(PasskeyProperties.class)
public class PasskeyAutoConfiguration {

  /**
   * Default {@link ApiKeyResolver}. Named to avoid clashing with the {@code passkeyApiKeyResolver}
   * convention used in single-RP-tenant setups; the auto-config bean is the fallback when no other
   * resolver is declared.
   */
  @Bean
  @ConditionalOnMissingBean(ApiKeyResolver.class)
  public ApiKeyResolver passkeyDefaultApiKeyResolver(PasskeyProperties props, BeanFactory bf) {
    if (props.getMultiTenant().isEnabled()) {
      String beanName = props.getMultiTenant().getResolverBean();
      try {
        return bf.getBean(beanName, ApiKeyResolver.class);
      } catch (BeansException e) {
        throw new IllegalStateException(
            "passkey.rp.multi-tenant.enabled=true but no ApiKeyResolver bean named '"
                + beanName
                + "' is declared. Register one with @Bean(\""
                + beanName
                + "\").",
            e);
      }
    }
    if (props.getBaseUrl() == null) {
      throw new IllegalStateException("passkey.rp.base-url must be set");
    }
    if (props.getApiKey() == null || props.getApiKey().isBlank()) {
      throw new IllegalStateException(
          "passkey.rp.api-key must be set for single-tenant mode (or enable multi-tenant)");
    }
    if (props.getTenantId() == null) {
      throw new IllegalStateException(
          "passkey.rp.tenant-id must be set for single-tenant mode so the JWT filter can verify"
              + " the tid claim");
    }
    return new FixedApiKeyResolver(props.getTenantId(), props.getApiKey());
  }

  @Bean
  @ConditionalOnMissingBean
  public PasskeyHttpClient passkeyHttpClient(PasskeyProperties props) {
    return new JdkPasskeyHttpClient(
        props.getBaseUrl(),
        props.getHttp().getConnectTimeout(),
        props.getHttp().getReadTimeout(),
        new RetryPolicy(props.getHttp().getMaxRetries(), props.getHttp().getRetryBaseBackoff()));
  }

  @Bean
  @ConditionalOnMissingBean
  public PasskeyClient passkeyClient(
      PasskeyHttpClient http, ApiKeyResolver resolver, PasskeyProperties props) {
    return props.getMultiTenant().isEnabled()
        ? new MultiTenantPasskeyClient(http, resolver)
        : new DefaultPasskeyClient(http, resolver);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtVerifier passkeyJwtVerifier(PasskeyProperties props) {
    return new NimbusJwtVerifier(
        props.effectiveJwksUri(),
        props.getJwksCacheTtl(),
        props.getIssuer(),
        props.getAuth().getJwt().getClockSkew());
  }

  @Bean
  @ConditionalOnMissingBean
  public RefreshTokenManager passkeyRefreshTokenManager(PasskeyClient client) {
    return new RefreshTokenManager(client);
  }
}
