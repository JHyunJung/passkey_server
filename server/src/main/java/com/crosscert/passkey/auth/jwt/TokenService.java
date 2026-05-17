package com.crosscert.passkey.auth.jwt;

import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * HMAC-SHA256 signed JWT issuance for end-user sessions.
 *
 * <p>Access tokens are stateless (signature + typ check). Refresh tokens are stateful: every issued
 * refresh records a {@link RefreshToken} row keyed by its {@code jti}, allowing per-token
 * revocation, family-wide revocation on reuse detection, and audit-grade lifecycle traceability.
 *
 * <p>Verification is split into {@link #verifyAccess} and {@link #verifyRefresh}: each rejects
 * tokens whose {@code typ} claim does not match, preventing refresh tokens being used as access
 * tokens (or vice versa).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

  private static final String TYP_ACCESS = "access";
  private static final String TYP_REFRESH = "refresh";

  private final JwtProperties props;
  private final RefreshTokenRepository refreshRepo;

  private SecretKey key() {
    byte[] keyBytes = props.secret().getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
      throw new IllegalStateException("passkey.jwt.secret must be at least 32 bytes");
    }
    return Keys.hmacShaKeyFor(keyBytes);
  }

  /**
   * Returns the previous signing key when rotation is in progress, otherwise {@code null}. Used
   * only for verification fallback — outstanding tokens signed with the previous secret continue to
   * verify until they expire/rotate onto the primary key.
   */
  private SecretKey previousKey() {
    if (!props.hasPreviousSecret()) {
      return null;
    }
    byte[] keyBytes = props.previousSecret().getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  /**
   * First-time issuance after a successful authentication ceremony. The persisted {@link
   * RefreshToken} has {@code parentJti=null} (root of a new rotation family).
   */
  @Transactional
  public TokenPair issue(UUID tenantId, UUID tenantUserId, String externalUserId) {
    return issueInternal(tenantId, tenantUserId, externalUserId, null, null, null);
  }

  /** Same as {@link #issue} with client metadata captured for forensics. */
  @Transactional
  public TokenPair issue(
      UUID tenantId, UUID tenantUserId, String externalUserId, String clientIp, String userAgent) {
    return issueInternal(tenantId, tenantUserId, externalUserId, null, clientIp, userAgent);
  }

  /**
   * Rotates a refresh token: verify → revoke (ROTATED) → issue a new pair whose refresh row links
   * back to the rotated token via {@code parent_jti}. If the presented token is already revoked,
   * the entire rotation family is burned ({@link ErrorCode#REFRESH_TOKEN_REUSED}).
   *
   * <p>Tenant context comes from the token's {@code tid} claim (signed by the server) — the caller
   * does not need to read {@code TenantContextHolder} explicitly. The X-API-Key chain still pins
   * the RP identity at the network layer.
   */
  @Transactional
  public TokenPair rotate(String presentedRefresh, String clientIp, String userAgent) {
    Claims claims = parseSigned(presentedRefresh, TYP_REFRESH);
    UUID jti = parseJti(claims);
    UUID userId = UUID.fromString(claims.getSubject());
    UUID tenantId = parseTid(claims);
    String externalUserId = claims.get("xuid", String.class);

    Optional<RefreshToken> opt = refreshRepo.findByIdAndTenantUserId(jti, userId);
    if (opt.isEmpty()) {
      log.warn("token.refresh.unknown_jti tenantId={} userId={} jti={}", tenantId, userId, jti);
      throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
    }
    RefreshToken row = opt.get();
    if (row.isRevoked()) {
      // Reuse detected → burn the family + audit trail.
      int burned =
          refreshRepo.revokeFamily(
              userId,
              row.rootJti(),
              RevokedReason.REUSE_DETECTED,
              OffsetDateTime.now(ZoneOffset.UTC));
      log.error(
          "token.refresh.reuse_detected tenantId={} userId={} jti={} rootJti={} burned={}",
          tenantId,
          userId,
          jti,
          row.rootJti(),
          burned);
      throw new BusinessException(ErrorCode.REFRESH_TOKEN_REUSED);
    }
    if (row.isExpired()) {
      throw new BusinessException(ErrorCode.EXPIRED_TOKEN);
    }

    row.revoke(RevokedReason.ROTATED);
    return issueInternal(tenantId, userId, externalUserId, row.getId(), clientIp, userAgent);
  }

  /** Verifies a token and rejects anything that is not an access token. Stateless. */
  public Claims verifyAccess(String token) {
    return parseSigned(token, TYP_ACCESS);
  }

  /**
   * Verifies a refresh token: signature + typ + DB row exists and is not revoked. Used by callers
   * who want to inspect the claims without rotating (rare — most callers want {@link #rotate}).
   */
  @Transactional(readOnly = true)
  public Claims verifyRefresh(String token) {
    Claims claims = parseSigned(token, TYP_REFRESH);
    UUID jti = parseJti(claims);
    UUID userId = UUID.fromString(claims.getSubject());
    RefreshToken row =
        refreshRepo
            .findByIdAndTenantUserId(jti, userId)
            .orElseThrow(() -> new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED));
    if (row.isRevoked()) {
      throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
    }
    if (row.isExpired()) {
      throw new BusinessException(ErrorCode.EXPIRED_TOKEN);
    }
    return claims;
  }

  private TokenPair issueInternal(
      UUID tenantId,
      UUID tenantUserId,
      String externalUserId,
      UUID parentJti,
      String clientIp,
      String userAgent) {
    Instant now = Instant.now();
    UUID jti = UUID.randomUUID();
    Instant refreshExp = now.plus(Duration.ofSeconds(props.refreshTtlSeconds()));

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
            .claim("xuid", externalUserId)
            .claim("typ", TYP_REFRESH)
            .id(jti.toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(refreshExp))
            .signWith(key())
            .compact();

    refreshRepo.save(
        RefreshToken.create(
            jti,
            tenantId,
            tenantUserId,
            parentJti,
            OffsetDateTime.ofInstant(refreshExp, ZoneOffset.UTC),
            clientIp,
            userAgent));

    return new TokenPair(access, refresh, props.accessTtlSeconds());
  }

  private Claims parseSigned(String token, String expectedTyp) {
    Claims claims;
    try {
      claims = Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload();
    } catch (JwtException primaryFailure) {
      // Rotation fallback: when a previous secret is configured, also accept tokens signed with it.
      // Outstanding tokens issued before the rotation keep working until they expire, at which
      // point the user rotates onto the primary key automatically.
      SecretKey prev = previousKey();
      if (prev == null) {
        throw new BusinessException(ErrorCode.INVALID_TOKEN, primaryFailure.getMessage());
      }
      try {
        claims = Jwts.parser().verifyWith(prev).build().parseSignedClaims(token).getPayload();
        log.debug("jwt.verified.with.previous.secret typ={}", expectedTyp);
      } catch (JwtException previousFailure) {
        throw new BusinessException(ErrorCode.INVALID_TOKEN, previousFailure.getMessage());
      }
    }
    String actualTyp = claims.get("typ", String.class);
    if (!expectedTyp.equals(actualTyp)) {
      throw new BusinessException(
          ErrorCode.INVALID_TOKEN, "wrong token type: expected " + expectedTyp);
    }
    return claims;
  }

  private static UUID parseTid(Claims claims) {
    String tid = claims.get("tid", String.class);
    if (tid == null || tid.isBlank()) {
      throw new BusinessException(ErrorCode.INVALID_TOKEN, "missing tid");
    }
    try {
      return UUID.fromString(tid);
    } catch (IllegalArgumentException e) {
      throw new BusinessException(ErrorCode.INVALID_TOKEN, "malformed tid");
    }
  }

  private static UUID parseJti(Claims claims) {
    String id = claims.getId();
    if (id == null || id.isBlank()) {
      throw new BusinessException(ErrorCode.INVALID_TOKEN, "missing jti");
    }
    try {
      return UUID.fromString(id);
    } catch (IllegalArgumentException e) {
      throw new BusinessException(ErrorCode.INVALID_TOKEN, "malformed jti");
    }
  }
}
