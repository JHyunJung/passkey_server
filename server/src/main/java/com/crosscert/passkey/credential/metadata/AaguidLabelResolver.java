package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * Resolves an AAGUID to a human-readable label by looking it up in the currently-cached MDS BLOB.
 * Falls back to the raw UUID string when (a) the BLOB hasn't loaded yet, or (b) the AAGUID isn't
 * registered in MDS (common for platform authenticators — iCloud Keychain, Windows Hello, Google
 * Password Manager are not in the FIDO MDS).
 *
 * <p>Caches the AAGUID→entry map to avoid an O(N) scan of {@code blob.entries()} per call. Cache is
 * rebuilt on {@link MdsBlobRefreshedEvent} — which fires from {@link MdsBlobProvider#refresh()} and
 * is guaranteed to land after listener registration (warm-up runs on {@code
 * ApplicationReadyEvent}).
 */
@Slf4j
@Service
public class AaguidLabelResolver {

  private final MdsBlobProvider provider;
  private volatile Map<UUID, MetadataEntry> cache;
  private volatile MetadataBlob cachedFor;

  public AaguidLabelResolver(MdsBlobProvider provider) {
    this.provider = provider;
  }

  public AaguidLabel resolve(UUID aaguid) {
    if (aaguid == null) {
      return new AaguidLabel(null, "unknown", false);
    }
    MetadataEntry entry = lookup(aaguid);
    if (entry == null || entry.description() == null) {
      return new AaguidLabel(aaguid, aaguid.toString(), false);
    }
    return new AaguidLabel(aaguid, entry.description(), true);
  }

  @EventListener(MdsBlobRefreshedEvent.class)
  public void onBlobRefresh(MdsBlobRefreshedEvent event) {
    // Drop the cache; next resolve() rebuilds from the new blob via lookup().
    this.cache = null;
    this.cachedFor = null;
    log.info("aaguid.cache.invalidated reason=blobRefresh");
  }

  private MetadataEntry lookup(UUID aaguid) {
    MetadataBlob current = provider.getLastBlob().get();
    if (current == null) {
      return null;
    }
    Map<UUID, MetadataEntry> snapshot = this.cache;
    if (snapshot == null || this.cachedFor != current) {
      snapshot = build(current.entries());
      this.cache = snapshot;
      this.cachedFor = current;
    }
    return snapshot.get(aaguid);
  }

  private static Map<UUID, MetadataEntry> build(List<MetadataEntry> entries) {
    Map<UUID, MetadataEntry> map = new HashMap<>(entries.size() * 2);
    for (MetadataEntry e : entries) {
      if (e != null && e.aaguid() != null) {
        map.put(e.aaguid(), e);
      }
    }
    return map;
  }
}
