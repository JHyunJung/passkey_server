package com.crosscert.passkey.credential.metadata;

import java.util.UUID;

/**
 * Result of {@link AaguidLabelResolver#resolve}. {@code fromMds=true} means the {@code displayName}
 * is the MDS metadataStatement description for a known authenticator; {@code false} means the MDS
 * BLOB had no entry for this AAGUID (platform authenticators like iCloud Keychain are common
 * MDS-misses) and {@code displayName} is the raw UUID string for display.
 */
public record AaguidLabel(UUID aaguid, String displayName, boolean fromMds) {}
