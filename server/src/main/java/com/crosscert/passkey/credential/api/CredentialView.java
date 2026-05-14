package com.crosscert.passkey.credential.api;

import com.crosscert.passkey.credential.domain.Credential;
import java.time.OffsetDateTime;
import java.util.UUID;

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
    OffsetDateTime createdAt) {

  public static CredentialView from(Credential c) {
    return new CredentialView(
        c.getId(),
        c.getTenantUserId(),
        c.getCredentialId(),
        c.getNickname(),
        c.getStatus().name(),
        c.getAaguid() == null ? null : c.getAaguid().toString(),
        c.getTransports(),
        c.getSignatureCounter(),
        c.getLastUsedAt(),
        c.getCreatedAt());
  }
}
