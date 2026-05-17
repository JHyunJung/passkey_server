package com.crosscert.passkey.credential.domain;

/**
 * Why a credential was revoked. Persisted as text in {@code credential.revoked_reason}; the same
 * value is shown to admins / RP CS when explaining "your passkey is no longer valid".
 */
public enum CredentialRevokedReason {
  /** End user invoked DELETE /api/v1/rp/passkeys/{id} themselves. */
  USER_REQUEST,
  /** Admin (PLATFORM_OPERATOR or RP_ADMIN) revoked via the admin console. */
  ADMIN_FORCED,
  /** Suspected key compromise — flagged manually during incident response. */
  COMPROMISE_SUSPECTED,
  /** Signature counter regression detected during an authenticate ceremony (FIDO clone signal). */
  SIGNATURE_COUNTER_REGRESSION,
  /** Credential aged out of the tenant's retention window (future automation). */
  LIFECYCLE_EXPIRED,
}
