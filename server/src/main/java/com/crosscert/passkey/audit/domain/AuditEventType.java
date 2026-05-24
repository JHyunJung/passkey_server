package com.crosscert.passkey.audit.domain;

/**
 * Audit-log event taxonomy. Grouped into five logical sections so that consumers (admin UI filter
 * chips, retention policies, downstream SIEM mappings) can categorize without string matching.
 * Order within each section is stable — append new entries at the end of their group, never
 * renumber.
 *
 * <p>Each value carries an {@link AuditCategory} for the cross-tenant Activity feed filter; that
 * mapping is the single source of truth used both by server aggregations and serialized response
 * payloads.
 */
public enum AuditEventType {

  // ---------- REGISTRATION ----------
  REGISTRATION_OPTIONS_REQUESTED(AuditCategory.CEREMONY),
  CREDENTIAL_REGISTERED(AuditCategory.CEREMONY),

  // ---------- AUTHENTICATION ----------
  AUTHENTICATION_OPTIONS_REQUESTED(AuditCategory.CEREMONY),
  CREDENTIAL_AUTHENTICATED(AuditCategory.CEREMONY),
  SIGNATURE_COUNTER_REGRESSION(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_AUTH_RATE_LIMIT(AuditCategory.SECURITY_FAIL),
  // CTAP 2.1 Backup State (BS) flag change. Emitted when a passkey's syncable status flips
  // between sessions (e.g. iCloud Keychain or Google Password Manager backup turning on/off).
  // Compliance-sensitive RPs use this to revoke or downgrade trust on backed-up credentials.
  CREDENTIAL_BACKUP_STATE_CHANGED(AuditCategory.CEREMONY),

  // ---------- CREDENTIAL_LIFECYCLE ----------
  CREDENTIAL_REVOKED(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_RENAMED(AuditCategory.ADMIN_ACTION),
  CREDENTIAL_REASSIGNED(AuditCategory.ADMIN_ACTION),
  ATTESTATION_TRUST_FAILED(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_AUTO_SUSPENDED(AuditCategory.SECURITY_FAIL),
  CREDENTIAL_UNSUSPENDED(AuditCategory.SECURITY_FAIL),

  // ---------- ADMIN ----------
  TENANT_CREATED(AuditCategory.ADMIN_ACTION),
  TENANT_SUSPENDED(AuditCategory.ADMIN_ACTION),
  TENANT_ACTIVATED(AuditCategory.ADMIN_ACTION),
  API_KEY_ISSUED(AuditCategory.ADMIN_ACTION),
  API_KEY_REVOKED(AuditCategory.ADMIN_ACTION),
  WEBAUTHN_CONFIG_UPDATED(AuditCategory.ADMIN_ACTION),
  ADMIN_USER_CREATED(AuditCategory.ADMIN_ACTION),
  ADMIN_USER_DELETED(AuditCategory.ADMIN_ACTION),
  ADMIN_USER_PASSWORD_RESET(AuditCategory.ADMIN_ACTION),
  USER_FORCE_LOGOUT(AuditCategory.ADMIN_ACTION),

  // ---------- SESSION ----------
  REFRESH_TOKEN_REVOKED(AuditCategory.ADMIN_ACTION);

  // ---------- SYSTEM ----------
  // Reserved for future hash-chain / scheduler / integration events. Currently unused.

  private final AuditCategory category;

  AuditEventType(AuditCategory category) {
    this.category = category;
  }

  public AuditCategory category() {
    return category;
  }
}
