package com.crosscert.passkey.credential.challenge;

import java.io.Serializable;
import java.util.UUID;

/**
 * Stored in Redis per-ceremony. Holds the random challenge bytes (base64url-encoded) plus context
 * needed to bind the assertion/attestation to this specific request.
 */
public record ChallengeRecord(
    String challengeB64u,
    UUID tenantId,
    UUID tenantUserId,
    CeremonyType ceremonyType,
    String userHandleB64u)
    implements Serializable {}
