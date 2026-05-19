package com.crosscert.passkey.rp.jwt;

/** Verifies access tokens issued by the passkey server. Refresh tokens are not handled here. */
public interface JwtVerifier {

  VerifiedToken verifyAccess(String token);
}
