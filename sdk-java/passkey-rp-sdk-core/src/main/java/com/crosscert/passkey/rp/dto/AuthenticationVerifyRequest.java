package com.crosscert.passkey.rp.dto;

import java.util.UUID;

public record AuthenticationVerifyRequest(
    UUID ceremonyId,
    String credentialId,
    String clientDataJsonB64u,
    String authenticatorDataB64u,
    String signatureB64u,
    String userHandleB64u) {}
