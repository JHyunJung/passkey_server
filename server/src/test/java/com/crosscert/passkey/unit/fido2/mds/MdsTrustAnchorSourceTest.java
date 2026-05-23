package com.crosscert.passkey.unit.fido2.mds;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MdsTrustAnchorSourceTest {

  private static final UUID AAGUID_A = UUID.fromString("00000000-0000-0000-0000-00000000000a");
  private static final UUID AAGUID_REVOKED =
      UUID.fromString("00000000-0000-0000-0000-0000000000bb");
  private static final UUID AAGUID_UNKNOWN =
      UUID.fromString("00000000-0000-0000-0000-0000000000cc");

  private static MdsTrustAnchorSource source() {
    return new MdsTrustAnchorSource(
        List.of(
            new MetadataEntry(AAGUID_A, List.of(), List.of(StatusReport.FIDO_CERTIFIED)),
            new MetadataEntry(AAGUID_REVOKED, List.of(), List.of(StatusReport.REVOKED))));
  }

  @Test
  void finds_entry_by_aaguid() {
    assertThat(source().findEntry(AAGUID_A)).isPresent();
  }

  @Test
  void returns_empty_for_unknown_aaguid() {
    assertThat(source().findEntry(AAGUID_UNKNOWN)).isEmpty();
  }

  @Test
  void reports_revoked_authenticator() {
    assertThat(source().findEntry(AAGUID_REVOKED))
        .get()
        .extracting(MetadataEntry::isRevoked)
        .isEqualTo(true);
  }

  @Test
  void null_aaguid_returns_empty() {
    assertThat(source().findEntry(null)).isEmpty();
  }
}
