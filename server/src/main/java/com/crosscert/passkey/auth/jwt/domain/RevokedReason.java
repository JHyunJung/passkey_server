package com.crosscert.passkey.auth.jwt.domain;

/**
 * Why a refresh token was revoked. Persisted as text in {@code refresh_token.revoked_reason} so
 * forensics queries can group / filter without a join.
 */
public enum RevokedReason {
  /** Normal rotation — the user exchanged this refresh for a new pair. */
  ROTATED,
  /** End-user explicitly logged out. */
  USER_LOGOUT,
  /** Underlying credential was revoked (admin or user). */
  CREDENTIAL_REVOKED,
  /** A previously-rotated token was reused — entire family burned. */
  REUSE_DETECTED,
  /** Admin action (forced sign-out / incident response). */
  ADMIN_FORCED,
  /** Underlying credential was auto-suspended by MDS revocation scan. */
  CREDENTIAL_SUSPENDED,
}
