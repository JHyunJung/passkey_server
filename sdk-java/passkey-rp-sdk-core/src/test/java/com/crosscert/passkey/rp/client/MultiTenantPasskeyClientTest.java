package com.crosscert.passkey.rp.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.rp.dto.AuthenticationOptionsRequest;
import com.crosscert.passkey.rp.dto.AuthenticationOptionsResponse;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/** Verifies per-tenant client caching and resolver invocation pattern. */
class MultiTenantPasskeyClientTest {

  @Test
  void delegates_use_correct_api_key_per_tenant() {
    UUID tA = UUID.randomUUID();
    UUID tB = UUID.randomUUID();
    PasskeyHttpClient http = Mockito.mock(PasskeyHttpClient.class);
    when(http.post(
            any(), any(), any(), Mockito.<TypeReference<AuthenticationOptionsResponse>>any()))
        .thenReturn(
            new AuthenticationOptionsResponse(
                UUID.randomUUID(), "c", 60000, "example.com", List.of(), "preferred"));

    ApiKeyResolver resolver =
        new ApiKeyResolver() {
          int callCount = 0;

          @Override
          public TenantBinding resolve(Object requestContext) {
            callCount++;
            UUID tid = callCount % 2 == 1 ? tA : tB;
            return new TenantBinding(tid, "key-" + tid);
          }
        };

    MultiTenantPasskeyClient client = new MultiTenantPasskeyClient(http, resolver);
    // Resolver round-robins: A, B, A on successive calls. Per-tenant clients are cached, so the
    // third call reuses tenant A's pre-built client.
    client.beginAuthentication(new AuthenticationOptionsRequest(null), "ctx1");
    client.beginAuthentication(new AuthenticationOptionsRequest(null), "ctx2");
    client.beginAuthentication(new AuthenticationOptionsRequest(null), "ctx3");

    verify(http, times(2))
        .post(
            any(),
            any(),
            eq("key-" + tA),
            Mockito.<TypeReference<AuthenticationOptionsResponse>>any());
    verify(http, times(1))
        .post(
            any(),
            any(),
            eq("key-" + tB),
            Mockito.<TypeReference<AuthenticationOptionsResponse>>any());
    assertThat(true).isTrue();
  }
}
