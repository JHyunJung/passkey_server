package com.crosscert.passkey.credential.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record RegistrationVerifyRequest(
    @NotNull UUID ceremonyId,
    @NotBlank String credentialId,
    @NotBlank String clientDataJsonB64u,
    @NotBlank String attestationObjectB64u,
    String transports,
    String nickname) {}
