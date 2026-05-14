package com.crosscert.passkey.credential.api;

import java.util.UUID;

public record RegistrationResult(UUID credentialDbId, String credentialId, String aaguid) {}
