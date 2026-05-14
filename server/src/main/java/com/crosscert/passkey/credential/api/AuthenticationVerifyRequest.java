package com.crosscert.passkey.credential.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AuthenticationVerifyRequest(
    @NotNull UUID ceremonyId,
    @NotBlank String credentialId,
    @NotBlank String clientDataJsonB64u,
    @NotBlank String authenticatorDataB64u,
    @NotBlank String signatureB64u,
    String userHandleB64u) {}
