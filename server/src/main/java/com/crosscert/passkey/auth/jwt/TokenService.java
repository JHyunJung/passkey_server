package com.crosscert.passkey.auth.jwt;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * HMAC-SHA256 signed JWT issuance for end-user sessions. M5 will introduce RS256 + key rotation;
 * for now the secret is taken from {@link JwtProperties}.
 *
 * <p>Verification is split into {@link #verifyAccess} and {@link #verifyRefresh}: each rejects
 * tokens whose {@code typ} claim does not match, preventing refresh tokens being used as access
 * tokens (or vice versa).
 */
@Service
@RequiredArgsConstructor
public class TokenService {

  private static final String TYP_ACCESS = "access";
  private static final String TYP_REFRESH = "refresh";

  private final JwtProperties props;

  private SecretKey key() {
    byte[] keyBytes = props.secret().getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
      throw new IllegalStateException("passkey.jwt.secret must be at least 32 bytes");
    }
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public TokenPair issue(UUID tenantId, UUID tenantUserId, String externalUserId) {
    Instant now = Instant.now();
    String access =
        Jwts.builder()
            .issuer(props.issuer())
            .subject(tenantUserId.toString())
            .claim("tid", tenantId.toString())
            .claim("xuid", externalUserId)
            .claim("typ", TYP_ACCESS)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(Duration.ofSeconds(props.accessTtlSeconds()))))
            .signWith(key())
            .compact();
    String refresh =
        Jwts.builder()
            .issuer(props.issuer())
            .subject(tenantUserId.toString())
            .claim("tid", tenantId.toString())
            .claim("typ", TYP_REFRESH)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(Duration.ofSeconds(props.refreshTtlSeconds()))))
            .signWith(key())
            .compact();
    return new TokenPair(access, refresh, props.accessTtlSeconds());
  }

  /** Verifies a token and rejects anything that is not an access token. */
  public Claims verifyAccess(String token) {
    return verify(token, TYP_ACCESS);
  }

  /** Verifies a token and rejects anything that is not a refresh token. */
  public Claims verifyRefresh(String token) {
    return verify(token, TYP_REFRESH);
  }

  private Claims verify(String token, String expectedTyp) {
    Claims claims;
    try {
      claims = Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload();
    } catch (JwtException e) {
      throw new BusinessException(ErrorCode.INVALID_TOKEN, e.getMessage());
    }
    String actualTyp = claims.get("typ", String.class);
    if (!expectedTyp.equals(actualTyp)) {
      throw new BusinessException(
          ErrorCode.INVALID_TOKEN, "wrong token type: expected " + expectedTyp);
    }
    return claims;
  }
}
