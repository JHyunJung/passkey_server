package com.crosscert.passkey.fido2.mds;

import java.security.cert.TrustAnchor;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Resolves FIDO MDS3 metadata by authenticator AAGUID. An attestation verifier in strict mode looks
 * up the {@link MetadataEntry} for the credential's AAGUID to (a) obtain the attestation
 * certificate trust anchors and (b) check the authenticator's revocation status.
 *
 * <p>Immutable — built from one parsed {@link MetadataBlob}'s entries. {@code MdsBlobProvider}
 * swaps in a fresh instance on each successful BLOB refresh.
 */
public final class MdsTrustAnchorSource {

  private final Map<UUID, MetadataEntry> byAaguid;

  public MdsTrustAnchorSource(List<MetadataEntry> entries) {
    Map<UUID, MetadataEntry> map = new HashMap<>();
    for (MetadataEntry entry : entries) {
      if (entry.aaguid() != null) {
        map.put(entry.aaguid(), entry);
      }
    }
    this.byAaguid = Map.copyOf(map);
  }

  /** Find the MDS entry for {@code aaguid}, or empty when the AAGUID is null or not in the BLOB. */
  public Optional<MetadataEntry> findEntry(UUID aaguid) {
    if (aaguid == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(byAaguid.get(aaguid));
  }

  /** The attestation-root trust anchors for {@code aaguid}, empty when the AAGUID is unknown. */
  public Set<TrustAnchor> trustAnchors(UUID aaguid) {
    return findEntry(aaguid)
        .map(
            e ->
                e.attestationRootCerts().stream()
                    .map(c -> new TrustAnchor(c, null))
                    .collect(Collectors.toSet()))
        .orElseGet(Set::of);
  }
}
