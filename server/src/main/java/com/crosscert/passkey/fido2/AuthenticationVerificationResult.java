package com.crosscert.passkey.fido2;

/**
 * Verified facts extracted from a successful assertion. The caller applies its own policy: {@code
 * newSignCount} feeds the existing {@code Credential.updateSignatureCounter()} clone detection, and
 * {@code backupState} drives the {@code CREDENTIAL_BACKUP_STATE_CHANGED} audit.
 */
public record AuthenticationVerificationResult(
    long newSignCount, boolean userVerified, boolean backupEligible, boolean backupState) {}
