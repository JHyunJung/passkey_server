package com.crosscert.passkey.rp.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.rp.RsaTestKeys;
import com.crosscert.passkey.rp.error.PasskeyAuthenticationException;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import java.net.URI;
import java.time.Duration;
import java.util.Date;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NimbusJwtVerifierTest {

  private WireMockServer wm;
  private RsaTestKeys keys;
  private NimbusJwtVerifier verifier;
  private static final String ISSUER = "passkey-platform";

  @BeforeEach
  void setUp() {
    wm = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wm.start();
    keys = new RsaTestKeys("test-kid");
    wm.stubFor(
        get(urlEqualTo("/.well-known/jwks.json"))
            .willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/jwk-set+json")
                    .withBody(keys.jwksJson())));
    verifier =
        new NimbusJwtVerifier(
            URI.create(wm.baseUrl() + "/.well-known/jwks.json"),
            Duration.ofMinutes(5),
            ISSUER,
            Duration.ofSeconds(60));
  }

  @AfterEach
  void tearDown() {
    wm.stop();
  }

  @Test
  void valid_token_roundtrips() throws Exception {
    String tid = "00000000-0000-0000-0000-000000000001";
    String sub = "00000000-0000-0000-0000-000000000002";
    String tok =
        keys.issueAccess(
            ISSUER, tid, sub, "alice", Date.from(java.time.Instant.now().plusSeconds(300)));
    VerifiedToken v = verifier.verifyAccess(tok);
    assertThat(v.tenantId().toString()).isEqualTo(tid);
    assertThat(v.tenantUserId().toString()).isEqualTo(sub);
    assertThat(v.externalUserId()).isEqualTo("alice");
  }

  @Test
  void wrong_issuer_rejected() throws Exception {
    String tok =
        keys.issueAccess(
            "rogue",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "alice",
            Date.from(java.time.Instant.now().plusSeconds(300)));
    assertThatThrownBy(() -> verifier.verifyAccess(tok))
        .isInstanceOf(PasskeyAuthenticationException.class);
  }

  @Test
  void expired_token_rejected() throws Exception {
    String tok =
        keys.issueAccess(
            ISSUER,
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "alice",
            Date.from(java.time.Instant.now().minusSeconds(600)));
    assertThatThrownBy(() -> verifier.verifyAccess(tok))
        .isInstanceOf(PasskeyAuthenticationException.class);
  }

  @Test
  void wrong_kid_rejected() throws Exception {
    RsaTestKeys rogueKeys = new RsaTestKeys("rogue-kid");
    String tok =
        rogueKeys.issueAccess(
            ISSUER,
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "alice",
            Date.from(java.time.Instant.now().plusSeconds(300)));
    assertThatThrownBy(() -> verifier.verifyAccess(tok))
        .isInstanceOf(PasskeyAuthenticationException.class);
  }
}
