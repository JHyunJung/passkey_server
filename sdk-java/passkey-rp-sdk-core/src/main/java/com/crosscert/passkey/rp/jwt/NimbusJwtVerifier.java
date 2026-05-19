package com.crosscert.passkey.rp.jwt;

import com.crosscert.passkey.rp.error.ErrorCode;
import com.crosscert.passkey.rp.error.PasskeyAuthenticationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * RS256 + JWKS verifier backed by {@code nimbus-jose-jwt}. Nimbus's built-in refresh-ahead cache is
 * enabled so the JWKS endpoint is hit at most once per cache window even under load.
 *
 * <p>Asserts:
 *
 * <ul>
 *   <li>signature against a kid in the JWKS,
 *   <li>{@code iss} matches the configured issuer,
 *   <li>{@code typ=access} (rejects refresh-token-as-access confusion),
 *   <li>{@code iat}/{@code exp} within clock skew.
 * </ul>
 */
public final class NimbusJwtVerifier implements JwtVerifier {

  private final ConfigurableJWTProcessor<SecurityContext> processor;

  public NimbusJwtVerifier(URI jwksUri, Duration cacheTtl, String issuer, Duration clockSkew) {
    try {
      URL url = jwksUri.toURL();
      // Refresh-ahead must satisfy: ttl > refreshAhead + cacheRefreshTimeout (Nimbus invariant).
      // We pick refresh-ahead = max(ttl/3, 30s) so even very short TTLs (tests, dev) are valid.
      long ttlMs = cacheTtl.toMillis();
      long refreshAheadMs = Math.max(ttlMs / 3, 30_000L);
      long cacheRefreshTimeoutMs = Math.max(ttlMs / 30, 5_000L);
      // Guard: collapse to plain cache when the invariant cannot be satisfied.
      if (ttlMs <= refreshAheadMs + cacheRefreshTimeoutMs) {
        refreshAheadMs = ttlMs / 4;
        cacheRefreshTimeoutMs = Math.min(cacheRefreshTimeoutMs, ttlMs / 10);
      }
      JWKSource<SecurityContext> source =
          JWKSourceBuilder.create(url)
              .cache(ttlMs, cacheRefreshTimeoutMs)
              .refreshAheadCache(refreshAheadMs, false)
              .build();
      DefaultJWTProcessor<SecurityContext> p = new DefaultJWTProcessor<>();
      p.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, source));
      Set<String> required = new HashSet<>();
      required.add("sub");
      required.add("tid");
      required.add("xuid");
      required.add("typ");
      required.add("iat");
      required.add("exp");
      JWTClaimsSet exact = new JWTClaimsSet.Builder().issuer(issuer).build();
      DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
          new DefaultJWTClaimsVerifier<>(exact, required);
      claimsVerifier.setMaxClockSkew((int) clockSkew.toSeconds());
      p.setJWTClaimsSetVerifier(claimsVerifier);
      this.processor = p;
    } catch (Exception e) {
      throw new IllegalStateException("cannot configure JwtVerifier", e);
    }
  }

  @Override
  public VerifiedToken verifyAccess(String token) {
    JWTClaimsSet claims;
    try {
      claims = processor.process(token, null);
    } catch (Exception e) {
      throw new PasskeyAuthenticationException(
          mapToErrorCode(e), errorCodeText(e), 401, e.getMessage(), null);
    }
    try {
      String typ = claims.getStringClaim("typ");
      if (!"access".equals(typ)) {
        throw new PasskeyAuthenticationException(
            ErrorCode.INVALID_TOKEN, "A004", 401, "wrong token type", null);
      }
      UUID tid = UUID.fromString(claims.getStringClaim("tid"));
      UUID sub = UUID.fromString(claims.getSubject());
      String xuid = claims.getStringClaim("xuid");
      Instant iat = claims.getIssueTime().toInstant();
      Date exp = claims.getExpirationTime();
      return new VerifiedToken(tid, sub, xuid, iat, exp == null ? null : exp.toInstant());
    } catch (ParseException e) {
      throw new PasskeyAuthenticationException(
          ErrorCode.INVALID_TOKEN, "A004", 401, e.getMessage(), null);
    }
  }

  private static ErrorCode mapToErrorCode(Exception e) {
    String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase(java.util.Locale.ROOT);
    if (msg.contains("expired")) return ErrorCode.EXPIRED_TOKEN;
    return ErrorCode.INVALID_TOKEN;
  }

  private static String errorCodeText(Exception e) {
    return mapToErrorCode(e).code();
  }
}
