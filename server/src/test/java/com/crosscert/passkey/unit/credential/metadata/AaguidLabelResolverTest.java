package com.crosscert.passkey.unit.credential.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.credential.metadata.AaguidLabel;
import com.crosscert.passkey.credential.metadata.AaguidLabelResolver;
import com.crosscert.passkey.credential.metadata.MdsBlobProvider;
import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AaguidLabelResolverTest {

  @Test
  void resolve_null_returnsUnknown() {
    AaguidLabelResolver resolver = newResolverWithBlob(null);
    AaguidLabel label = resolver.resolve(null);
    assertThat(label.aaguid()).isNull();
    assertThat(label.displayName()).isEqualTo("unknown");
    assertThat(label.fromMds()).isFalse();
  }

  @Test
  void resolve_blobMissing_returnsUuidStringAndFromMdsFalse() {
    UUID aaguid = UUID.randomUUID();
    AaguidLabelResolver resolver = newResolverWithBlob(null);
    AaguidLabel label = resolver.resolve(aaguid);
    assertThat(label.aaguid()).isEqualTo(aaguid);
    assertThat(label.displayName()).isEqualTo(aaguid.toString());
    assertThat(label.fromMds()).isFalse();
  }

  @Test
  void resolve_blobMiss_returnsUuidStringAndFromMdsFalse() {
    UUID present = UUID.randomUUID();
    UUID missing = UUID.randomUUID();
    AaguidLabelResolver resolver = newResolverWithEntries(List.of(entry(present, "YubiKey 5")));
    AaguidLabel label = resolver.resolve(missing);
    assertThat(label.displayName()).isEqualTo(missing.toString());
    assertThat(label.fromMds()).isFalse();
  }

  @Test
  void resolve_blobHit_returnsDescriptionAndFromMdsTrue() {
    UUID aaguid = UUID.randomUUID();
    AaguidLabelResolver resolver = newResolverWithEntries(List.of(entry(aaguid, "YubiKey 5C NFC")));
    AaguidLabel label = resolver.resolve(aaguid);
    assertThat(label.displayName()).isEqualTo("YubiKey 5C NFC");
    assertThat(label.fromMds()).isTrue();
  }

  @Test
  void onBlobRefresh_rebuildsCache() {
    UUID a = UUID.randomUUID();
    UUID b = UUID.randomUUID();
    MdsBlobProvider provider = mock(MdsBlobProvider.class);
    AtomicReference<MetadataBlob> ref = new AtomicReference<>(blobOf(List.of(entry(a, "A"))));
    when(provider.getLastBlob()).thenReturn(ref);
    AaguidLabelResolver resolver = new AaguidLabelResolver(provider);
    // warm the cache to the first blob
    assertThat(resolver.resolve(a).displayName()).isEqualTo("A");
    assertThat(resolver.resolve(b).fromMds()).isFalse();
    // simulate blob rotation
    ref.set(blobOf(List.of(entry(b, "B"))));
    resolver.onBlobRefresh(new MdsBlobRefreshedEvent(ref.get(), Instant.now()));
    assertThat(resolver.resolve(b).displayName()).isEqualTo("B");
    assertThat(resolver.resolve(a).fromMds()).isFalse();
  }

  // ---- helpers ------------------------------------------------------------

  private static AaguidLabelResolver newResolverWithBlob(MetadataBlob blob) {
    MdsBlobProvider provider = mock(MdsBlobProvider.class);
    when(provider.getLastBlob()).thenReturn(new AtomicReference<>(blob));
    return new AaguidLabelResolver(provider);
  }

  private static AaguidLabelResolver newResolverWithEntries(List<MetadataEntry> entries) {
    return newResolverWithBlob(blobOf(entries));
  }

  private static MetadataEntry entry(UUID aaguid, String description) {
    MetadataEntry e = mock(MetadataEntry.class);
    when(e.aaguid()).thenReturn(aaguid);
    when(e.description()).thenReturn(description);
    return e;
  }

  private static MetadataBlob blobOf(List<MetadataEntry> entries) {
    MetadataBlob blob = mock(MetadataBlob.class);
    when(blob.entries()).thenReturn(entries);
    return blob;
  }
}
