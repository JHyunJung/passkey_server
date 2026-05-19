package com.crosscert.passkey.auth.jwt;

import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * JWT issuance and verification.
 *
 * <p>Supports two signing algorithms, selectable via {@code passkey.jwt.algorithm}:
 *
 * <ul>
 *   <li>{@code HS256} — legacy HMAC-SHA256, env-provided 32-byte secret.
 *   <li>{@code RS256} — RSA-SHA256, env-provided PEM keypair. Public half exposed at {@code
 *       /.well-known/jwks.json} so RP backends verify locally.
 * </ul>
 *
 * <p>Issuance: HS256 uses {@code jjwt}; RS256 uses {@code nimbus-jose-jwt} so the {@code kid}
 * header is added cleanly. Verification uses {@code jjwt} throughout — it accepts both HMAC and RSA
 * keys — and tries every configured key (current + previous, both algorithms) so outstanding tokens
 * keep working across rotations and the HS→RS cutover.
 *
 * <p>Access tokens are stateless (signature + typ check). Refresh tokens are stateful: every issued
 * refresh records a {@link RefreshToken} row keyed by its {@code jti}, allowing per-token
 * revocation, family-wide revocation on reuse detection, and audit-grade lifecycle traceability.
 */
@Slf4j
@Service
public class TokenService {

  private static final String TYP_ACCESS = "access";
  private static final String TYP_REFRESH = "refresh";

  private final JwtProperties props;
  private final RefreshTokenRepository refreshRepo;
  private final io.micrometer.core.instrument.Counter tidMismatchCounter;
  private final io.micrometer.core.instrument.Counter reuseDetectedCounter;

  /** Loaded once at startup so per-request signing has zero PEM-parsing overhead. */
  private RSAPrivateKey rsaPrivateKey;

  private String currentKid;

  /** kid → public key. Includes both current and previous when rotation is in progress. */
  private final Map<String, RSAPublicKey> rsaPublicKeysByKid = new LinkedHashMap<>();

  public TokenService(
      JwtProperties props,
      RefreshTokenRepository refreshRepo,
      io.micrometer.core.instrument.MeterRegistry registry) {
    this.props = props;
    this.refreshRepo = refreshRepo;
    this.tidMismatchCounter =
        io.micrometer.core.instrument.Counter.builder("passkey.security.refresh_tid_mismatch")
            .register(registry);
    this.reuseDetectedCounter =
        io.micrometer.core.instrument.Counter.builder("passkey.security.refresh_reuse_detected")
            .register(registry);
  }

  @PostConstruct
  public void loadRsaKeys() {
    if (props.hasRsaKeypair()) {
      this.rsaPrivateKey = parsePrivate(props.rsaPrivatePem());
      this.rsaPublicKeysByKid.put(props.kid(), parsePublic(props.rsaPublicPem()));
      this.currentKid = props.kid();
    }
    if (props.hasPreviousRsaKeypair()) {
      this.rsaPublicKeysByKid.put(props.kidPrevious(), parsePublic(props.rsaPublicPemPrevious()));
    }
    if (props.isRs256() && rsaPrivateKey == null) {
      throw new IllegalStateException("RS256 selected but no RSA keypair could be loaded");
    }
  }

  /** Snapshot of RSA public keys for the JWKS controller. Insertion order: current first. */
  public Map<String, RSAPublicKey> rsaPublicKeysByKid() {
    // Map.copyOf does not preserve insertion order; LinkedHashMap copy does.
    return java.util.Collections.unmodifiableMap(new LinkedHashMap<>(rsaPublicKeysByKid));
  }

  private SecretKey hmacKey() {
    byte[] keyBytes = props.secret().getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
      throw new IllegalStateException("passkey.jwt.secret must be at least 32 bytes");
    }
    return Keys.hmacShaKeyFor(keyBytes);
  }

  private SecretKey previousHmacKey() {
    if (!props.hasPreviousSecret()) {
      return null;
    }
    return Keys.hmacShaKeyFor(props.previousSecret().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * First-time issuance after a successful authentication ceremony. The persisted {@link
   * RefreshToken} has {@code parentJti=null} (root of a new rotation family).
   */
  @Transactional
  public TokenPair issue(UUID tenantId, UUID tenantUserId, String externalUserId) {
    return issueInternal(tenantId, tenantUserId, externalUserId, null, null, null);
  }

  @Transactional
  public TokenPair issue(
      UUID tenantId, UUID tenantUserId, String externalUserId, String clientIp, String userAgent) {
    return issueInternal(tenantId, tenantUserId, externalUserId, null, clientIp, userAgent);
  }

  @Transactional
  public TokenPair rotate(String presentedRefresh, String clientIp, String userAgent) {
    Claims claims = parseSigned(presentedRefresh, TYP_REFRESH);
    UUID jti = parseJti(claims);
    UUID userId = UUID.fromString(claims.getSubject());
    UUID tenantId = parseTid(claims);
    String externalUserId = claims.get("xuid", String.class);

    TenantContextHolder.optional()
        .ifPresent(
            ctx -> {
              if (!ctx.tenantId().equals(tenantId)) {
                log.warn(
                    "token.refresh.tid_mismatch ambientTenantId={} claimTenantId={} jti={} "
                        + "clientIp={} userAgent={}",
                    ctx.tenantId(),
                    tenantId,
                    jti,
                    com.crosscert.passkey.common.log.LogSanitiser.forLog(clientIp),
                    com.crosscert.passkey.common.log.LogSanitiser.truncateUserAgent(userAgent));
                tidMismatchCounter.increment();
                throw new BusinessException(ErrorCode.INVALID_TOKEN, "tid mismatch");
              }
            });

    Optional<RefreshToken> opt = refreshRepo.findByIdAndTenantUserId(jti, userId);
    if (opt.isEmpty()) {
      log.warn("token.refresh.unknown_jti tenantId={} userId={} jti={}", tenantId, userId, jti);
      throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
    }
    RefreshToken row = opt.get();
    if (row.isRevoked()) {
      int burned =
          refreshRepo.revokeFamily(
              userId,
              row.rootJti(),
              RevokedReason.REUSE_DETECTED,
              OffsetDateTime.now(ZoneOffset.UTC));
      log.error(
          "token.refresh.reuse_detected tenantId={} userId={} jti={} rootJti={} burned={} "
              + "clientIp={} userAgent={}",
          tenantId,
          userId,
          jti,
          row.rootJti(),
          burned,
          com.crosscert.passkey.common.log.LogSanitiser.forLog(clientIp),
          com.crosscert.passkey.common.log.LogSanitiser.truncateUserAgent(userAgent));
      reuseDetectedCounter.increment();
      throw new BusinessException(ErrorCode.REFRESH_TOKEN_REUSED);
    }
    if (row.isExpired()) {
      throw new BusinessException(ErrorCode.EXPIRED_TOKEN);
    }

    row.revoke(RevokedReason.ROTATED);
    return issueInternal(tenantId, userId, externalUserId, row.getId(), clientIp, userAgent);
  }

  public Claims verifyAccess(String token) {
    return parseSigned(token, TYP_ACCESS);
  }

  @Transactional(readOnly = true)
  public Claims verifyRefresh(String token) {
    Claims claims = parseSigned(token, TYP_REFRESH);
    UUID jti = parseJti(claims);
    UUID userId = UUID.fromString(claims.getSubject());
    RefreshToken row =
        refreshRepo
            .findByIdAndTenantUserId(jti, userId)
            .orElseThrow(
                () -> {
                  log.warn("token.refresh.verify.unknown_jti userId={} jti={}", userId, jti);
                  return new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
                });
    if (row.isRevoked()) {
      log.warn(
          "token.refresh.verify.revoked userId={} jti={} reason={}",
          userId,
          jti,
          row.getRevokedReason());
      throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
    }
    if (row.isExpired()) {
      log.info("token.refresh.verify.expired userId={} jti={}", userId, jti);
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
    Instant accessExp = now.plus(Duration.ofSeconds(props.accessTtlSeconds()));
    Instant refreshExp = now.plus(Duration.ofSeconds(props.refreshTtlSeconds()));

    String access;
    String refresh;
    if (props.isRs256()) {
      access = signRs256(tenantId, tenantUserId, externalUserId, TYP_ACCESS, null, now, accessExp);
      refresh =
          signRs256(tenantId, tenantUserId, externalUserId, TYP_REFRESH, jti, now, refreshExp);
    } else {
      access = signHs256(tenantId, tenantUserId, externalUserId, TYP_ACCESS, null, now, accessExp);
      refresh =
          signHs256(tenantId, tenantUserId, externalUserId, TYP_REFRESH, jti, now, refreshExp);
    }

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

  private String signHs256(
      UUID tenantId,
      UUID tenantUserId,
      String externalUserId,
      String typ,
      UUID jti,
      Instant now,
      Instant exp) {
    var builder =
        Jwts.builder()
            .issuer(props.issuer())
            .subject(tenantUserId.toString())
            .claim("tid", tenantId.toString())
            .claim("xuid", externalUserId)
            .claim("typ", typ)
            .issuedAt(Date.from(now))
            .expiration(Date.from(exp));
    if (jti != null) {
      builder.id(jti.toString());
    }
    return builder.signWith(hmacKey()).compact();
  }

  private String signRs256(
      UUID tenantId,
      UUID tenantUserId,
      String externalUserId,
      String typ,
      UUID jti,
      Instant now,
      Instant exp) {
    JWTClaimsSet.Builder claims =
        new JWTClaimsSet.Builder()
            .issuer(props.issuer())
            .subject(tenantUserId.toString())
            .claim("tid", tenantId.toString())
            .claim("xuid", externalUserId)
            .claim("typ", typ)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(exp));
    if (jti != null) {
      claims.jwtID(jti.toString());
    }
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(currentKid).build();
    SignedJWT signed = new SignedJWT(header, claims.build());
    try {
      signed.sign(new RSASSASigner(rsaPrivateKey));
    } catch (JOSEException e) {
      throw new IllegalStateException("RS256 sign failed", e);
    }
    return signed.serialize();
  }

  /**
   * Verify a token by trying every configured key — HS primary, HS previous, then every RSA kid in
   * insertion order. The {@code kid} header (when present) short-circuits straight to the matching
   * RSA key. jjwt's parser accepts both {@link SecretKey} and RSA {@code PublicKey}, so a single
   * code path handles both algorithms.
   */
  private Claims parseSigned(String token, String expectedTyp) {
    Claims claims = null;
    JwtException lastFailure = null;

    String kid = peekKid(token);
    String alg = peekAlgorithm(token);

    List<SecretKey> hmacCandidates = new ArrayList<>(2);
    List<RSAPublicKey> rsaCandidates = new ArrayList<>(4);
    boolean rsToken = JWSAlgorithm.RS256.getName().equals(alg);
    if (rsToken) {
      if (kid != null && rsaPublicKeysByKid.containsKey(kid)) {
        rsaCandidates.add(rsaPublicKeysByKid.get(kid));
      } else {
        rsaCandidates.addAll(rsaPublicKeysByKid.values());
      }
    } else {
      if (props.hasHmacSecret()) {
        hmacCandidates.add(hmacKey());
        SecretKey prev = previousHmacKey();
        if (prev != null) {
          hmacCandidates.add(prev);
        }
      }
      rsaCandidates.addAll(rsaPublicKeysByKid.values());
    }

    for (SecretKey candidate : hmacCandidates) {
      try {
        claims = Jwts.parser().verifyWith(candidate).build().parseSignedClaims(token).getPayload();
        break;
      } catch (JwtException e) {
        lastFailure = e;
      }
    }
    if (claims == null) {
      for (PublicKey candidate : rsaCandidates) {
        try {
          claims =
              Jwts.parser().verifyWith(candidate).build().parseSignedClaims(token).getPayload();
          break;
        } catch (JwtException e) {
          lastFailure = e;
        }
      }
    }

    if (claims == null) {
      String reason = lastFailure == null ? "no candidate keys" : lastFailure.getMessage();
      log.warn("jwt.verify.failed typ={} reason={}", expectedTyp, reason);
      throw new BusinessException(ErrorCode.INVALID_TOKEN, reason);
    }

    String actualTyp = claims.get("typ", String.class);
    if (!expectedTyp.equals(actualTyp)) {
      log.warn(
          "jwt.verify.wrong_typ expected={} actual={} jti={}",
          expectedTyp,
          actualTyp,
          claims.getId());
      throw new BusinessException(
          ErrorCode.INVALID_TOKEN, "wrong token type: expected " + expectedTyp);
    }
    return claims;
  }

  private static String peekAlgorithm(String token) {
    try {
      return SignedJWT.parse(token).getHeader().getAlgorithm().getName();
    } catch (ParseException | NullPointerException e) {
      return null;
    }
  }

  private static String peekKid(String token) {
    try {
      return SignedJWT.parse(token).getHeader().getKeyID();
    } catch (ParseException e) {
      return null;
    }
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

  private static RSAPrivateKey parsePrivate(String pem) {
    try {
      byte[] der = pemToDer(pem, "PRIVATE KEY");
      return (RSAPrivateKey)
          KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (Exception e) {
      throw new IllegalStateException("Cannot parse RSA private PEM", e);
    }
  }

  private static RSAPublicKey parsePublic(String pem) {
    try {
      byte[] der = pemToDer(pem, "PUBLIC KEY");
      return (RSAPublicKey)
          KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    } catch (Exception e) {
      throw new IllegalStateException("Cannot parse RSA public PEM", e);
    }
  }

  private static byte[] pemToDer(String pem, String label) {
    String trimmed =
        pem.replace("-----BEGIN " + label + "-----", "")
            .replace("-----END " + label + "-----", "")
            .replaceAll("\\s+", "");
    return Base64.getDecoder().decode(trimmed);
  }
}
