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
 */
@Service
@RequiredArgsConstructor
public class TokenService {

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
            .claim("typ", "access")
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(Duration.ofSeconds(props.accessTtlSeconds()))))
            .signWith(key())
            .compact();
    String refresh =
        Jwts.builder()
            .issuer(props.issuer())
            .subject(tenantUserId.toString())
            .claim("tid", tenantId.toString())
            .claim("typ", "refresh")
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(Duration.ofSeconds(props.refreshTtlSeconds()))))
            .signWith(key())
            .compact();
    return new TokenPair(access, refresh, props.accessTtlSeconds());
  }

  public Claims verify(String token) {
    try {
      return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload();
    } catch (JwtException e) {
      throw new BusinessException(ErrorCode.INVALID_TOKEN, e.getMessage());
    }
  }
}
