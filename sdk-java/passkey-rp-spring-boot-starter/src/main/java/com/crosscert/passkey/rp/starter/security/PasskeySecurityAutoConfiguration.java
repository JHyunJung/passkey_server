package com.crosscert.passkey.rp.starter.security;

import com.crosscert.passkey.rp.jwt.JwtVerifier;
import com.crosscert.passkey.rp.starter.PasskeyProperties;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Optional Spring Security wiring. When {@code passkey.rp.auth.mode=jwt} (the default) we mount
 * {@link PasskeyJwtAuthenticationFilter} in front of {@code UsernamePasswordAuthenticationFilter}.
 *
 * <p>RP apps that want their own SecurityFilterChain can simply declare one with higher precedence
 * — the bean here is gated by {@code @ConditionalOnMissingBean(SecurityFilterChain.class)}.
 */
@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
public class PasskeySecurityAutoConfiguration {

  @Bean
  public PasskeyJwtAuthenticationFilter passkeyJwtAuthenticationFilter(
      JwtVerifier verifier, ApiKeyResolver resolver, PasskeyProperties props) {
    return new PasskeyJwtAuthenticationFilter(verifier, resolver, props);
  }

  @Bean
  @ConditionalOnProperty(name = "passkey.rp.auth.mode", havingValue = "session")
  public PasskeySessionAuthenticationSuccessHandler passkeySessionSuccessHandler(
      PasskeyProperties props) {
    return new PasskeySessionAuthenticationSuccessHandler(props);
  }

  @Bean
  @ConditionalOnMissingBean(SecurityFilterChain.class)
  @ConditionalOnProperty(name = "passkey.rp.auth.mode", havingValue = "jwt", matchIfMissing = true)
  public SecurityFilterChain passkeyDefaultFilterChain(
      org.springframework.security.config.annotation.web.builders.HttpSecurity http,
      PasskeyJwtAuthenticationFilter filter)
      throws Exception {
    return http.csrf(csrf -> csrf.disable())
        .sessionManagement(
            sm ->
                sm.sessionCreationPolicy(
                    org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
        .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }
}
