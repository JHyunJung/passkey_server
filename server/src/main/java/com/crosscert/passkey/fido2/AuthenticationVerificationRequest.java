package com.crosscert.passkey.fido2;

import java.util.List;

/**
 * Inputs for verifying a {@code navigator.credentials.get()} assertion. All byte arrays are the raw
 * (already base64url-decoded) values; {@code expectedChallenge} is the raw challenge bytes the
 * server issued. {@code storedCoseKeyBytes} is the credential public key recorded at registration —
 * for this server, the {@code credential.public_key_cose} column.
 */
public record AuthenticationVerificationRequest(
    byte[] authenticatorData,
    byte[] clientDataJson,
    byte[] signature,
    byte[] expectedChallenge,
    List<String> expectedOrigins,
    String expectedRpId,
    byte[] storedCoseKeyBytes,
    boolean userVerificationRequired) {}
