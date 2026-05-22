/**
 * Credential (passkey) namespace (M2). Ceremonies and lifecycle. Registration/authentication
 * verification for the default (non-strict) path runs on the in-house FIDO2 core in {@code
 * com.crosscert.passkey.fido2}; the strict (mdsStrict) path still uses webauthn4j for MDS-backed
 * attestation trust until Milestone B replaces it.
 */
package com.crosscert.passkey.credential;
