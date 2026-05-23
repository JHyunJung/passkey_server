package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MetadataBlob;
import java.time.Instant;

/**
 * Published by {@link MdsBlobProvider#refresh()} after a successful BLOB fetch + verify. Consumed
 * asynchronously by {@link MdsRevocationScanListener} on the {@code auditExecutor} pool so the
 * refresh transaction does not block on cross-tenant credential UPDATEs.
 */
public record MdsBlobRefreshedEvent(MetadataBlob blob, Instant refreshedAt) {}
