package com.crosscert.passkey.fido2.mds;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

/**
 * One FIDO MDS3 metadata BLOB entry, keyed by authenticator AAGUID. {@code attestationRootCerts}
 * are the trust anchors an authenticator's attestation certificate chain must chain up to; {@code
 * statusReports} carries the authenticator's FIDO certification / revocation status. {@code
 * description} is the human-readable name from {@code metadataStatement.description} (e.g. "YubiKey
 * 5C NFC"); {@code null} when the BLOB entry has no metadataStatement or no description.
 */
public record MetadataEntry(
    UUID aaguid,
    List<X509Certificate> attestationRootCerts,
    List<StatusReport> statusReports,
    String description) {

  /**
   * Legacy 3-arg constructor (no description) — kept for source compatibility with existing tests.
   */
  public MetadataEntry(
      UUID aaguid, List<X509Certificate> attestationRootCerts, List<StatusReport> statusReports) {
    this(aaguid, attestationRootCerts, statusReports, null);
  }

  /**
   * Whether this authenticator has a critical (revoked / compromised) status and must be refused
   * regardless of tenant policy.
   */
  public boolean isRevoked() {
    return statusReports.stream().anyMatch(StatusReport::isCritical);
  }
}
