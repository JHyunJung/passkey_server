package com.crosscert.passkey.credential.api;

import jakarta.validation.constraints.NotBlank;

public record RegistrationBeginRequest(
    @NotBlank String externalUserId, @NotBlank String displayName) {}
