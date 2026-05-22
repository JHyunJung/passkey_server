package com.crosscert.passkey.fido2;

/**
 * Verified facts extracted from a successful registration. The caller persists these and applies
 * tenant policy: {@code aaguid} feeds the AAGUID allow-list, {@code backupEligible} feeds the
 * syncable-credential policy. {@code attestedCredentialData} is the serialized {@code aaguid ||
 * credIdLen || credentialId || coseKey} blob — the exact form stored in {@code
 * credential.public_key_cose} and read back by {@code AuthenticationVerifier}.
 */
public record RegistrationVerificationResult(
    byte[] credentialId,
    byte[] attestedCredentialData,
    byte[] aaguid,
    long signCount,
    boolean userVerified,
    boolean backupEligible,
    boolean backupState,
    String attestationFormat) {}
