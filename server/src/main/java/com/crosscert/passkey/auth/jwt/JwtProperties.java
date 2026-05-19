package com.crosscert.passkey.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT signing/verification configuration.
 *
 * <p>Supports two algorithms:
 *
 * <ul>
 *   <li>{@code HS256} — legacy symmetric. Cleared by the end of the RS256 cutover window.
 *   <li>{@code RS256} — asymmetric RSA 2048. Public key exposed via {@code /.well-known/jwks.json}
 *       so RP backends can verify locally without sharing a secret.
 * </ul>
 *
 * <p>Rotation is supported per algorithm via the {@code *_PREVIOUS} variants. During the HS→RS
 * cutover the server signs with whichever {@code algorithm} is selected but accepts tokens from
 * either family for verification — outstanding access/refresh tokens keep working until they
 * expire.
 */
@ConfigurationProperties(prefix = "passkey.jwt")
public record JwtProperties(
    String issuer,
    String algorithm,
    String secret,
    String previousSecret,
    String rsaPrivatePem,
    String rsaPublicPem,
    String kid,
    String rsaPrivatePemPrevious,
    String rsaPublicPemPrevious,
    String kidPrevious,
    long accessTtlSeconds,
    long refreshTtlSeconds) {

  public static final String ALG_HS256 = "HS256";
  public static final String ALG_RS256 = "RS256";

  public JwtProperties {
    if (algorithm == null || algorithm.isBlank()) {
      algorithm = ALG_HS256;
    }
    algorithm = algorithm.toUpperCase(Locale.ROOT);
    if (!ALG_HS256.equals(algorithm) && !ALG_RS256.equals(algorithm)) {
      throw new IllegalStateException(
          "passkey.jwt.algorithm must be HS256 or RS256 (got " + algorithm + ")");
    }

    boolean hsConfigured = secret != null && !secret.isBlank();
    boolean rsConfigured =
        rsaPrivatePem != null
            && !rsaPrivatePem.isBlank()
            && rsaPublicPem != null
            && !rsaPublicPem.isBlank();

    if (ALG_HS256.equals(algorithm) && !hsConfigured) {
      throw new IllegalStateException("passkey.jwt.secret must be set when algorithm=HS256");
    }
    if (ALG_RS256.equals(algorithm)) {
      if (!rsConfigured) {
        throw new IllegalStateException(
            "passkey.jwt.rsa-private-pem and rsa-public-pem must be set when algorithm=RS256");
      }
      if (kid == null || kid.isBlank()) {
        throw new IllegalStateException("passkey.jwt.kid must be set when algorithm=RS256");
      }
    }

    if (hsConfigured && secret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalStateException(
          "passkey.jwt.secret must be at least 32 bytes (got "
              + secret.getBytes(StandardCharsets.UTF_8).length
              + ")");
    }
    if (previousSecret != null
        && !previousSecret.isBlank()
        && previousSecret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalStateException(
          "passkey.jwt.previous-secret must be at least 32 bytes when set (got "
              + previousSecret.getBytes(StandardCharsets.UTF_8).length
              + ")");
    }

    boolean rsPrevPartial =
        (rsaPrivatePemPrevious != null && !rsaPrivatePemPrevious.isBlank())
            ^ (rsaPublicPemPrevious != null && !rsaPublicPemPrevious.isBlank());
    if (rsPrevPartial) {
      throw new IllegalStateException(
          "passkey.jwt.rsa-{private,public}-pem-previous must be set together or not at all");
    }
    boolean rsPrevConfigured =
        rsaPrivatePemPrevious != null
            && !rsaPrivatePemPrevious.isBlank()
            && rsaPublicPemPrevious != null
            && !rsaPublicPemPrevious.isBlank();
    if (rsPrevConfigured && (kidPrevious == null || kidPrevious.isBlank())) {
      throw new IllegalStateException(
          "passkey.jwt.kid-previous must be set when a previous RSA keypair is configured");
    }

    if (issuer == null || issuer.isBlank()) {
      issuer = "passkey-platform";
    }
    if (accessTtlSeconds <= 0) {
      accessTtlSeconds = 900;
    }
    if (refreshTtlSeconds <= 0) {
      refreshTtlSeconds = 2_592_000;
    }
  }

  /** True when a previous HMAC secret is configured and HS-side rotation is in progress. */
  public boolean hasPreviousSecret() {
    return previousSecret != null && !previousSecret.isBlank();
  }

  /** True when an HMAC secret is configured at all (covers cutover where HS verify is needed). */
  public boolean hasHmacSecret() {
    return secret != null && !secret.isBlank();
  }

  /** True when an RSA keypair is configured (primary). */
  public boolean hasRsaKeypair() {
    return rsaPrivatePem != null
        && !rsaPrivatePem.isBlank()
        && rsaPublicPem != null
        && !rsaPublicPem.isBlank();
  }

  /** True when a previous RSA keypair is configured (rotation). */
  public boolean hasPreviousRsaKeypair() {
    return rsaPrivatePemPrevious != null
        && !rsaPrivatePemPrevious.isBlank()
        && rsaPublicPemPrevious != null
        && !rsaPublicPemPrevious.isBlank();
  }

  public boolean isRs256() {
    return ALG_RS256.equals(algorithm);
  }
}
