package com.crosscert.passkey.rp.starter.web;

import com.crosscert.passkey.rp.client.PasskeyClient;
import com.crosscert.passkey.rp.jwt.RefreshTokenManager;
import com.crosscert.passkey.rp.starter.PasskeyProperties;
import com.crosscert.passkey.rp.starter.security.PasskeySessionAuthenticationSuccessHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnWebApplication
public class PasskeyWebAutoConfiguration {

  @Bean
  public PasskeyMdcFilter passkeyMdcFilter(PasskeyProperties props) {
    return new PasskeyMdcFilter(props);
  }

  @Bean
  public PasskeyExceptionHandler passkeyExceptionHandler() {
    return new PasskeyExceptionHandler();
  }

  @Bean
  @ConditionalOnProperty(
      name = "passkey.rp.ceremony.controller-enabled",
      havingValue = "true",
      matchIfMissing = true)
  public PasskeyCeremonyController passkeyCeremonyController(
      PasskeyClient client,
      RefreshTokenManager refreshManager,
      ObjectProvider<PasskeySessionAuthenticationSuccessHandler> sessionHandler,
      PasskeyProperties props) {
    return new PasskeyCeremonyController(client, refreshManager, sessionHandler, props);
  }
}
