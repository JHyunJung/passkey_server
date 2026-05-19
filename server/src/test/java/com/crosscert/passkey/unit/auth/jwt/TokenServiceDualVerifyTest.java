package com.crosscert.passkey.unit.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.auth.jwt.JwtProperties;
import com.crosscert.passkey.auth.jwt.TokenPair;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.Claims;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Covers the HS→RS cutover and the previous-RSA-key rotation window: a server running RS256 primary
 * must still accept tokens signed with the previous kid, and a server running HS256 with an RSA
 * keypair also configured must accept RS256-signed tokens (so an upstream issuer can flip before
 * this server does).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenServiceDualVerifyTest {

  @Mock private RefreshTokenRepository refreshRepo;

  @Test
  void server_in_rs256_mode_accepts_token_signed_by_previous_kid() {
    RsaTestKeys current = RsaTestKeys.generate();
    RsaTestKeys previous = RsaTestKeys.generate();

    // Old server: only "previous" keypair, signs with "old-kid".
    JwtProperties oldProps =
        new JwtProperties(
            "passkey-test",
            "RS256",
            null,
            null,
            previous.privatePem,
            previous.publicPem,
            "old-kid",
            null,
            null,
            null,
            900L,
            2_592_000L);
    TokenService oldServer = service(oldProps);
    when(refreshRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
    TokenPair issuedByOld = oldServer.issue(UUID.randomUUID(), UUID.randomUUID(), "alice");

    // New server: primary "new-kid", previous "old-kid" still trusted for verify.
    JwtProperties newProps =
        new JwtProperties(
            "passkey-test",
            "RS256",
            null,
            null,
            current.privatePem,
            current.publicPem,
            "new-kid",
            previous.privatePem,
            previous.publicPem,
            "old-kid",
            900L,
            2_592_000L);
    TokenService newServer = service(newProps);

    Claims claims = newServer.verifyAccess(issuedByOld.accessToken());
    assertThat(claims.get("typ", String.class)).isEqualTo("access");
  }

  @Test
  void server_in_hs256_mode_with_rsa_keypair_also_accepts_rs256_tokens() {
    RsaTestKeys keys = RsaTestKeys.generate();

    // Upstream issuer in RS256 mode.
    JwtProperties rsProps =
        new JwtProperties(
            "passkey-test",
            "RS256",
            null,
            null,
            keys.privatePem,
            keys.publicPem,
            "rs-kid",
            null,
            null,
            null,
            900L,
            2_592_000L);
    TokenService rsIssuer = service(rsProps);
    when(refreshRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
    TokenPair issued = rsIssuer.issue(UUID.randomUUID(), UUID.randomUUID(), "bob");

    // Server still in HS256 issue mode but RSA verifier already deployed.
    JwtProperties hsWithRs =
        new JwtProperties(
            "passkey-test",
            "HS256",
            "0123456789abcdef0123456789abcdef",
            null,
            keys.privatePem,
            keys.publicPem,
            "rs-kid",
            null,
            null,
            null,
            900L,
            2_592_000L);
    TokenService hsServer = service(hsWithRs);

    Claims claims = hsServer.verifyAccess(issued.accessToken());
    assertThat(claims.get("xuid", String.class)).isEqualTo("bob");
  }

  private TokenService service(JwtProperties props) {
    TokenService s =
        new TokenService(
            props, refreshRepo, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    s.loadRsaKeys();
    return s;
  }
}
