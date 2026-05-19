package com.crosscert.passkey.rp.starter;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.rp.client.DefaultPasskeyClient;
import com.crosscert.passkey.rp.client.MultiTenantPasskeyClient;
import com.crosscert.passkey.rp.client.PasskeyClient;
import com.crosscert.passkey.rp.jwt.JwtVerifier;
import com.crosscert.passkey.rp.jwt.RefreshTokenManager;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import com.crosscert.passkey.rp.tenant.FixedApiKeyResolver;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Verifies the Boot autoconfig wires every default bean and respects override switches. */
class PasskeyAutoConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(PasskeyAutoConfiguration.class))
          .withPropertyValues(
              "passkey.rp.base-url=http://localhost:0",
              "passkey.rp.api-key=test-key",
              "passkey.rp.tenant-id=00000000-0000-0000-0000-000000000001");

  @Test
  void single_tenant_defaults_provide_all_beans() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasSingleBean(PasskeyClient.class)
                .hasSingleBean(JwtVerifier.class)
                .hasSingleBean(RefreshTokenManager.class)
                .hasSingleBean(ApiKeyResolver.class)
                .getBean(ApiKeyResolver.class)
                .isInstanceOf(FixedApiKeyResolver.class));
  }

  @Test
  void single_tenant_client_is_default_implementation() {
    runner.run(
        ctx ->
            assertThat(ctx.getBean(PasskeyClient.class)).isInstanceOf(DefaultPasskeyClient.class));
  }

  @Test
  void multi_tenant_picks_multi_tenant_client_and_requires_resolver_bean() {
    runner
        .withPropertyValues("passkey.rp.multi-tenant.enabled=true")
        .withUserConfiguration(MultiTenantConfig.class)
        .run(
            ctx -> {
              assertThat(ctx.getBean(PasskeyClient.class))
                  .isInstanceOf(MultiTenantPasskeyClient.class);
            });
  }

  @Test
  void multi_tenant_without_resolver_bean_fails_fast() {
    runner
        .withPropertyValues("passkey.rp.multi-tenant.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              Throwable failure = ctx.getStartupFailure();
              boolean foundIllegalState = false;
              for (Throwable t = failure; t != null; t = t.getCause()) {
                if (t instanceof IllegalStateException
                    && t.getMessage() != null
                    && t.getMessage().contains("multi-tenant.enabled=true")) {
                  foundIllegalState = true;
                  break;
                }
              }
              assertThat(foundIllegalState)
                  .as(
                      "startup failure chain should contain IllegalStateException about multi-tenant")
                  .isTrue();
            });
  }

  @Configuration
  static class MultiTenantConfig {
    @Bean("passkeyApiKeyResolver")
    ApiKeyResolver resolver() {
      return ctx ->
          new ApiKeyResolver.TenantBinding(
              java.util.UUID.fromString("00000000-0000-0000-0000-000000000001"), "k");
    }
  }
}
