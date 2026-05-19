package com.crosscert.passkey.rp.client;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.patch;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.rp.dto.AuthenticationOptionsRequest;
import com.crosscert.passkey.rp.dto.AuthenticationVerifyRequest;
import com.crosscert.passkey.rp.dto.RegistrationBeginRequest;
import com.crosscert.passkey.rp.dto.RegistrationVerifyRequest;
import com.crosscert.passkey.rp.error.ChallengeExpiredException;
import com.crosscert.passkey.rp.error.PasskeyRateLimitException;
import com.crosscert.passkey.rp.error.RefreshReuseDetectedException;
import com.crosscert.passkey.rp.tenant.FixedApiKeyResolver;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import java.net.URI;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Each happy-path endpoint is stubbed once; the error paths exercise the envelope-to-exception
 * translation that production traffic depends on.
 */
class DefaultPasskeyClientWireMockTest {

  private WireMockServer wm;
  private PasskeyClient client;
  private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000001");
  private static final String API_KEY = "test-api-key";

  @BeforeEach
  void setUp() {
    wm = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wm.start();
    PasskeyHttpClient http =
        new JdkPasskeyHttpClient(
            URI.create(wm.baseUrl()),
            Duration.ofSeconds(2),
            Duration.ofSeconds(5),
            new RetryPolicy(2, Duration.ofMillis(20)));
    client = new DefaultPasskeyClient(http, new FixedApiKeyResolver(TENANT, API_KEY));
  }

  @AfterEach
  void tearDown() {
    wm.stop();
  }

  @Test
  void register_begin_returns_options_and_forwards_api_key() {
    wm.stubFor(
        post(urlEqualTo("/api/v1/rp/passkeys/register/options"))
            .withHeader("X-API-Key", equalTo(API_KEY))
            .willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {"success":true,"code":"OK","message":"ok",
                         "data":{"ceremonyId":"22222222-0000-0000-0000-000000000000",
                                 "challenge":"chal","rp":{"id":"example.com","name":"Example"},
                                 "user":{"id":"u","name":"alice","displayName":"Alice"},
                                 "pubKeyCredParams":[{"type":"public-key","alg":-7}],
                                 "timeout":60000,"attestation":"none",
                                 "authenticatorSelection":{"userVerification":"preferred",
                                   "residentKey":"preferred","requireResidentKey":false}},
                         "traceId":"t"}
                        """)));

    var options = client.beginRegistration(new RegistrationBeginRequest("alice", "Alice"), null);
    assertThat(options.challenge()).isEqualTo("chal");
    assertThat(options.rp().id()).isEqualTo("example.com");
  }

  @Test
  void register_verify_p002_surfaces_challenge_expired() {
    wm.stubFor(
        post(urlEqualTo("/api/v1/rp/passkeys/register/verify"))
            .willReturn(
                aResponse()
                    .withStatus(400)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {"success":false,"code":"P002","message":"Challenge expired",
                         "error":{"errorCode":"P002"},"traceId":"t"}
                        """)));

    assertThatThrownBy(
            () ->
                client.finishRegistration(
                    new RegistrationVerifyRequest(
                        UUID.randomUUID(), "cid", "cdj", "ao", "internal", null),
                    null))
        .isInstanceOf(ChallengeExpiredException.class)
        .extracting(e -> ((ChallengeExpiredException) e).traceId())
        .isEqualTo("t");
  }

  @Test
  void authenticate_options_supports_discoverable_flow() {
    wm.stubFor(
        post(urlEqualTo("/api/v1/rp/passkeys/authenticate/options"))
            .willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {"success":true,"code":"OK","message":"ok",
                         "data":{"ceremonyId":"33333333-0000-0000-0000-000000000000",
                                 "challenge":"c","timeout":60000,"rpId":"example.com",
                                 "allowCredentials":[],"userVerification":"preferred"},
                         "traceId":"t"}
                        """)));

    var opts = client.beginAuthentication(new AuthenticationOptionsRequest(null), null);
    assertThat(opts.rpId()).isEqualTo("example.com");
    assertThat(opts.allowCredentials()).isEmpty();
  }

  @Test
  void authenticate_verify_returns_tokens() {
    wm.stubFor(
        post(urlEqualTo("/api/v1/rp/passkeys/authenticate/verify"))
            .willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {"success":true,"code":"OK","message":"ok",
                         "data":{"credentialDbId":"11111111-0000-0000-0000-000000000000",
                                 "tenantUserId":"00000000-0000-0000-0000-000000000099",
                                 "credentialId":"cid","signatureCounter":3,
                                 "accessToken":"a","refreshToken":"r","accessExpiresIn":900},
                         "traceId":"t"}
                        """)));

    var result =
        client.finishAuthentication(
            new AuthenticationVerifyRequest(UUID.randomUUID(), "cid", "cdj", "ad", "sig", null),
            null);
    assertThat(result.accessToken()).isEqualTo("a");
    assertThat(result.refreshToken()).isEqualTo("r");
  }

  @Test
  void list_credentials_passes_external_user_id_query() {
    wm.stubFor(
        get(urlPathEqualTo("/api/v1/rp/passkeys"))
            .withQueryParam("externalUserId", equalTo("alice"))
            .willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        "{\"success\":true,\"code\":\"OK\",\"message\":\"ok\",\"data\":[],\"traceId\":\"t\"}")));

    assertThat(client.listCredentials("alice", null)).isEmpty();
  }

  @Test
  void delete_credential_emits_204_with_query() {
    UUID id = UUID.randomUUID();
    wm.stubFor(
        delete(urlPathEqualTo("/api/v1/rp/passkeys/" + id))
            .withQueryParam("externalUserId", equalTo("alice"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        "{\"success\":true,\"code\":\"OK\",\"message\":\"ok\",\"data\":null,\"traceId\":\"t\"}")));

    client.deleteCredential(id, "alice", null);
  }

  @Test
  void rename_credential_returns_updated_view() {
    UUID id = UUID.fromString("99999999-0000-0000-0000-000000000000");
    wm.stubFor(
        patch(urlPathEqualTo("/api/v1/rp/passkeys/" + id))
            .willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {"success":true,"code":"OK","message":"ok",
                         "data":{"id":"%s","tenantUserId":"00000000-0000-0000-0000-000000000099",
                                 "credentialId":"cid","nickname":"new","status":"ACTIVE",
                                 "aaguid":null,"transports":"internal","signatureCounter":1,
                                 "lastUsedAt":null,"createdAt":"2026-05-19T10:00:00Z",
                                 "revokedAt":null,"revokedReason":null},
                         "traceId":"t"}
                        """
                            .formatted(id))));

    var view = client.renameCredential(id, "alice", "new", null);
    assertThat(view.nickname()).isEqualTo("new");
  }

  @Test
  void refresh_a012_surfaces_reuse_detected() {
    wm.stubFor(
        post(urlEqualTo("/api/v1/rp/auth/refresh"))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {"success":false,"code":"A012","message":"Refresh token reuse detected",
                         "error":{"errorCode":"A012"},"traceId":"t"}
                        """)));

    assertThatThrownBy(() -> client.refresh("stolen", null))
        .isInstanceOf(RefreshReuseDetectedException.class);
  }

  @Test
  void rate_limit_429_after_retries_exhausted_surfaces_typed_exception() {
    wm.stubFor(
        post(urlEqualTo("/api/v1/rp/passkeys/register/options"))
            .willReturn(
                aResponse()
                    .withStatus(429)
                    .withHeader("Content-Type", "application/json")
                    .withHeader("Retry-After", "1")
                    .withBody(
                        "{\"success\":false,\"code\":\"R001\",\"message\":\"Rate limited\",\"traceId\":\"t\"}")));

    assertThatThrownBy(() -> client.beginRegistration(new RegistrationBeginRequest("a", "A"), null))
        .isInstanceOf(PasskeyRateLimitException.class)
        .extracting(e -> ((PasskeyRateLimitException) e).retryAfter())
        .isEqualTo(Duration.ofSeconds(1));
  }
}
