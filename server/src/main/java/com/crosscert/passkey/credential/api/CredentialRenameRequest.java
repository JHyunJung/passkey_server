package com.crosscert.passkey.credential.api;

import jakarta.validation.constraints.Size;

public record CredentialRenameRequest(@Size(max = 100) String nickname) {}
