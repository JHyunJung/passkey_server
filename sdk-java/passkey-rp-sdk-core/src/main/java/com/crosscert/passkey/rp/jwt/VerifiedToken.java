package com.crosscert.passkey.rp.jwt;

import java.time.Instant;
import java.util.UUID;

/** A verified access JWT. Only the claims an RP cares about are exposed. */
public record VerifiedToken(
    UUID tenantId, UUID tenantUserId, String externalUserId, Instant issuedAt, Instant expiresAt) {}
