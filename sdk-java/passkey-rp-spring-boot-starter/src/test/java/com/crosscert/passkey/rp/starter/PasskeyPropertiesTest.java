package com.crosscert.passkey.rp.starter;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import org.junit.jupiter.api.Test;

class PasskeyPropertiesTest {

  @Test
  void effective_jwks_uri_defaults_to_base_url_plus_well_known() {
    PasskeyProperties p = new PasskeyProperties();
    p.setBaseUrl(URI.create("https://passkey.example.com/"));
    assertThat(p.effectiveJwksUri())
        .isEqualTo(URI.create("https://passkey.example.com/.well-known/jwks.json"));
  }

  @Test
  void explicit_jwks_uri_overrides_default() {
    PasskeyProperties p = new PasskeyProperties();
    p.setBaseUrl(URI.create("https://passkey.example.com"));
    p.setJwksUri(URI.create("https://other.example.com/keys.json"));
    assertThat(p.effectiveJwksUri()).isEqualTo(URI.create("https://other.example.com/keys.json"));
  }
}
