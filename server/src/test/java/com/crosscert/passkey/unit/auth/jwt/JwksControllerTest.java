package com.crosscert.passkey.unit.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.auth.jwt.JwksController;
import com.crosscert.passkey.auth.jwt.JwtProperties;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.ResponseEntity;

/** JWKS endpoint exposes every configured RSA public key, marked sig + RS256, kid populated. */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwksControllerTest {

  @Mock private RefreshTokenRepository refreshRepo;

  @Test
  void single_rsa_key_returns_one_entry() {
    RsaTestKeys k = RsaTestKeys.generate();
    JwksController ctrl = controller(k, "kid-A", null, null);

    ResponseEntity<Map<String, Object>> resp = ctrl.jwks();
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) resp.getBody().get("keys");
    assertThat(keys).hasSize(1);
    Map<String, Object> jwk = keys.get(0);
    assertThat(jwk.get("kty")).isEqualTo("RSA");
    assertThat(jwk.get("use")).isEqualTo("sig");
    assertThat(jwk.get("alg")).isEqualTo("RS256");
    assertThat(jwk.get("kid")).isEqualTo("kid-A");
    // public material only — no private exponent leaks
    assertThat(jwk).doesNotContainKey("d");
  }

  @Test
  void rotation_returns_both_kids_current_first() {
    RsaTestKeys cur = RsaTestKeys.generate();
    RsaTestKeys prev = RsaTestKeys.generate();
    JwksController ctrl = controller(cur, "new", prev, "old");

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) ctrl.jwks().getBody().get("keys");
    assertThat(keys).hasSize(2);
    assertThat(keys.get(0).get("kid")).isEqualTo("new");
    assertThat(keys.get(1).get("kid")).isEqualTo("old");
  }

  @Test
  void hs256_only_server_returns_empty_keyset() {
    JwtProperties props =
        new JwtProperties(
            "iss",
            "HS256",
            "0123456789abcdef0123456789abcdef",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            900L,
            2_592_000L);
    TokenService svc =
        new TokenService(
            props, refreshRepo, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    svc.loadRsaKeys();
    JwksController ctrl = new JwksController(svc);
    @SuppressWarnings("unchecked")
    List<Object> keys = (List<Object>) ctrl.jwks().getBody().get("keys");
    assertThat(keys).isEmpty();
  }

  private JwksController controller(
      RsaTestKeys current, String currentKid, RsaTestKeys previous, String previousKid) {
    JwtProperties props =
        new JwtProperties(
            "iss",
            "RS256",
            null,
            null,
            current.privatePem,
            current.publicPem,
            currentKid,
            previous != null ? previous.privatePem : null,
            previous != null ? previous.publicPem : null,
            previousKid,
            900L,
            2_592_000L);
    TokenService svc =
        new TokenService(
            props, refreshRepo, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    svc.loadRsaKeys();
    return new JwksController(svc);
  }
}
