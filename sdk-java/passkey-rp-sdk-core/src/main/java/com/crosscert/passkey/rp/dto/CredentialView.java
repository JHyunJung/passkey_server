package com.crosscert.passkey.rp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.OffsetDateTime;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialView(
    UUID id,
    UUID tenantUserId,
    String credentialId,
    String nickname,
    String status,
    String aaguid,
    String transports,
    long signatureCounter,
    OffsetDateTime lastUsedAt,
    OffsetDateTime createdAt,
    OffsetDateTime revokedAt,
    String revokedReason) {}
