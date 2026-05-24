package com.crosscert.passkey.audit.domain;

/**
 * Audit-log event taxonomy. Grouped into five logical sections so that consumers (admin UI filter
 * chips, retention policies, downstream SIEM mappings) can categorize without string matching.
 * Order within each section is stable — append new entries at the end of their group, never
 * renumber.
 */
public enum AuditEventType {

  // ---------- REGISTRATION ----------
  REGISTRATION_OPTIONS_REQUESTED,
  CREDENTIAL_REGISTERED,

  // ---------- AUTHENTICATION ----------
  AUTHENTICATION_OPTIONS_REQUESTED,
  CREDENTIAL_AUTHENTICATED,
  SIGNATURE_COUNTER_REGRESSION,
  CREDENTIAL_AUTH_RATE_LIMIT,
  // CTAP 2.1 Backup State (BS) flag change. Emitted when a passkey's syncable status flips
  // between sessions (e.g. iCloud Keychain or Google Password Manager backup turning on/off).
  // Compliance-sensitive RPs use this to revoke or downgrade trust on backed-up credentials.
  CREDENTIAL_BACKUP_STATE_CHANGED,

  // ---------- CREDENTIAL_LIFECYCLE ----------
  CREDENTIAL_REVOKED,
  CREDENTIAL_RENAMED,
  CREDENTIAL_REASSIGNED,
  ATTESTATION_TRUST_FAILED,
  CREDENTIAL_AUTO_SUSPENDED,
  CREDENTIAL_UNSUSPENDED,

  // ---------- ADMIN ----------
  TENANT_CREATED,
  TENANT_SUSPENDED,
  TENANT_ACTIVATED,
  API_KEY_ISSUED,
  API_KEY_REVOKED,
  WEBAUTHN_CONFIG_UPDATED,
  ADMIN_USER_CREATED,
  ADMIN_USER_DELETED,
  ADMIN_USER_PASSWORD_RESET,
  USER_FORCE_LOGOUT,
  /**
   * Admin revoked a single refresh token by id (per-session control). Sibling of USER_FORCE_LOGOUT
   * which mass-revokes; this is the targeted "kill one device" lever.
   */
  REFRESH_TOKEN_REVOKED,

// ---------- SYSTEM ----------
// Reserved for future hash-chain / scheduler / integration events. Currently unused.
;
}
