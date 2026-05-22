package com.crosscert.passkey.fido2;

import java.util.List;

/**
 * Inputs for verifying a {@code navigator.credentials.create()} registration. {@code
 * attestationObject} and {@code clientDataJson} are the raw (base64url-decoded) ceremony outputs;
 * {@code expectedChallenge} is the raw challenge the server issued.
 */
public record RegistrationVerificationRequest(
    byte[] attestationObject,
    byte[] clientDataJson,
    byte[] expectedChallenge,
    List<String> expectedOrigins,
    String expectedRpId,
    boolean userVerificationRequired) {}
