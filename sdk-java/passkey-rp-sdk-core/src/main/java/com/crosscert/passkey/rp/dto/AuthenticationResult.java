package com.crosscert.passkey.rp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthenticationResult(
    UUID credentialDbId,
    UUID tenantUserId,
    String credentialId,
    long signatureCounter,
    String accessToken,
    String refreshToken,
    long accessExpiresIn) {}
