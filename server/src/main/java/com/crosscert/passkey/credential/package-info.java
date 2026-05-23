/**
 * Credential (passkey) namespace (M2). Ceremonies and lifecycle. Registration/authentication
 * verification for the default (non-strict) path runs on the in-house FIDO2 core in {@code
 * com.crosscert.passkey.fido2}; the strict (mdsStrict) path validates the attestation certificate
 * chain against MDS-sourced trust anchors via the in-house {@code com.crosscert.passkey.fido2.mds}
 * parser (Milestone B Phase 4 — webauthn4j removed).
 */
package com.crosscert.passkey.credential;
