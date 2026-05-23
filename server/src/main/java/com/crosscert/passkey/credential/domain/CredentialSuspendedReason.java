package com.crosscert.passkey.credential.domain;

/**
 * Why a credential was auto-suspended. The DB column {@code credential.suspended_reason} holds
 * {@code <category>:<detail>} (e.g. {@code "MDS_REVOKED:ATTESTATION_KEY_COMPROMISE"}). This enum is
 * the category — the detail varies per category (MDS StatusReport name, etc.).
 *
 * <p>Single value at MVP; reserved as a category space for future suspension triggers
 * (signature-counter regression auto, admin temporary block).
 */
public enum CredentialSuspendedReason {
  /** Detected during {@code MdsRevocationScanService.scan} — AAGUID critical in current BLOB. */
  MDS_REVOKED
}
