package com.crosscert.passkey.credential.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * RP-facing rename payload. Requires {@code externalUserId} so the server can prove the calling
 * end-user actually owns the credential — RP-facing endpoints authenticate the RP backend via
 * X-API-Key, not the end-user, so within-tenant ownership must be enforced at the application
 * layer. The admin console uses {@link CredentialRenameRequest} which has no such requirement
 * (admin acts on behalf of any user under their tenant).
 */
public record RpCredentialRenameRequest(
    @NotBlank String externalUserId, @Size(max = 100) String nickname) {}
