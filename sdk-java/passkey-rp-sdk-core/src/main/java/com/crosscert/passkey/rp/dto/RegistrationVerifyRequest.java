package com.crosscert.passkey.rp.dto;

import java.util.UUID;

public record RegistrationVerifyRequest(
    UUID ceremonyId,
    String credentialId,
    String clientDataJsonB64u,
    String attestationObjectB64u,
    String transports,
    String nickname) {}
