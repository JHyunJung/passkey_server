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

  // ---------- CREDENTIAL_LIFECYCLE ----------
  CREDENTIAL_REVOKED,
  CREDENTIAL_RENAMED,
  CREDENTIAL_REASSIGNED,
  ATTESTATION_TRUST_FAILED,

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

// ---------- SYSTEM ----------
// Reserved for future hash-chain / scheduler / integration events. Currently unused.
;
}
