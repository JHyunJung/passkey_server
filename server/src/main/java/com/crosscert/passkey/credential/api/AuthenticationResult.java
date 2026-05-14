package com.crosscert.passkey.credential.api;

import java.util.UUID;

public record AuthenticationResult(
    UUID credentialDbId,
    UUID tenantUserId,
    String credentialId,
    long signatureCounter,
    String accessToken,
    String refreshToken,
    long accessExpiresIn) {}
