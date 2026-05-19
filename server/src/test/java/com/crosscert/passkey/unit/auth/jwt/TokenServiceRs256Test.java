package com.crosscert.passkey.unit.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.auth.jwt.JwtProperties;
import com.crosscert.passkey.auth.jwt.TokenPair;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/** Round-trip + kid behaviour for the RS256 issue/verify path. */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenServiceRs256Test {

  @Mock private RefreshTokenRepository refreshRepo;
  private TokenService service;
  private static final String KID = "2026-05-A";

  @BeforeEach
  void setUp() {
    RsaTestKeys keys = RsaTestKeys.generate();
    JwtProperties props =
        new JwtProperties(
            "passkey-test",
            "RS256",
            null,
            null,
            keys.privatePem,
            keys.publicPem,
            KID,
            null,
            null,
            null,
            900L,
            2_592_000L);
    service =
        new TokenService(
            props, refreshRepo, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    service.loadRsaKeys();
    when(refreshRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
  }

  @Test
  void issued_access_token_carries_rs256_alg_and_kid() throws Exception {
    TokenPair issued = service.issue(UUID.randomUUID(), UUID.randomUUID(), "alice");
    SignedJWT parsed = SignedJWT.parse(issued.accessToken());
    assertThat(parsed.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    assertThat(parsed.getHeader().getKeyID()).isEqualTo(KID);
  }

  @Test
  void roundtrip_verify_access_returns_claims() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    TokenPair issued = service.issue(tenantId, userId, "alice");
    Claims claims = service.verifyAccess(issued.accessToken());
    assertThat(claims.get("typ", String.class)).isEqualTo("access");
    assertThat(claims.get("tid", String.class)).isEqualTo(tenantId.toString());
    assertThat(claims.getSubject()).isEqualTo(userId.toString());
    assertThat(claims.get("xuid", String.class)).isEqualTo("alice");
  }

  @Test
  void access_token_cannot_be_used_as_refresh() {
    TokenPair issued = service.issue(UUID.randomUUID(), UUID.randomUUID(), "alice");
    assertThatThrownBy(() -> service.verifyRefresh(issued.accessToken()))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.INVALID_TOKEN);
  }

  @Test
  void token_signed_by_unrelated_key_is_rejected() {
    RsaTestKeys other = RsaTestKeys.generate();
    JwtProperties other_props =
        new JwtProperties(
            "passkey-test",
            "RS256",
            null,
            null,
            other.privatePem,
            other.publicPem,
            "rogue",
            null,
            null,
            null,
            900L,
            2_592_000L);
    TokenService rogue =
        new TokenService(
            other_props,
            refreshRepo,
            new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    rogue.loadRsaKeys();
    TokenPair issued = rogue.issue(UUID.randomUUID(), UUID.randomUUID(), "eve");

    assertThatThrownBy(() -> service.verifyAccess(issued.accessToken()))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.INVALID_TOKEN);
  }
}
