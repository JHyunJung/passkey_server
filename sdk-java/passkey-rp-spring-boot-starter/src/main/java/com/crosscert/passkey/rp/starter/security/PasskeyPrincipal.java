package com.crosscert.passkey.rp.starter.security;

import com.crosscert.passkey.rp.jwt.VerifiedToken;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

/**
 * Principal that ends up in {@code SecurityContext} after a successful passkey authentication.
 * Serializable so Spring Session can persist it in Redis when running in session mode.
 */
public record PasskeyPrincipal(
    UUID tenantId, UUID tenantUserId, String externalUserId, Instant expiresAt)
    implements Serializable {

  public static PasskeyPrincipal from(VerifiedToken token) {
    return new PasskeyPrincipal(
        token.tenantId(), token.tenantUserId(), token.externalUserId(), token.expiresAt());
  }
}
