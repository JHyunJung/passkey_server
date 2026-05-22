package com.crosscert.passkey.unit.fido2.mds;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MetadataEntryTest {

  @Test
  void entry_with_revoked_status_is_revoked() {
    MetadataEntry entry =
        new MetadataEntry(
            UUID.fromString("00000000-0000-0000-0000-000000000001"),
            List.of(),
            List.of(StatusReport.FIDO_CERTIFIED, StatusReport.REVOKED));
    assertThat(entry.isRevoked()).isTrue();
  }

  @Test
  void entry_with_attestation_key_compromise_is_revoked() {
    MetadataEntry entry =
        new MetadataEntry(
            UUID.randomUUID(), List.of(), List.of(StatusReport.ATTESTATION_KEY_COMPROMISE));
    assertThat(entry.isRevoked()).isTrue();
  }

  @Test
  void entry_with_only_certified_status_is_not_revoked() {
    MetadataEntry entry =
        new MetadataEntry(UUID.randomUUID(), List.of(), List.of(StatusReport.FIDO_CERTIFIED));
    assertThat(entry.isRevoked()).isFalse();
  }

  @Test
  void status_report_critical_classification() {
    assertThat(StatusReport.REVOKED.isCritical()).isTrue();
    assertThat(StatusReport.ATTESTATION_KEY_COMPROMISE.isCritical()).isTrue();
    assertThat(StatusReport.USER_VERIFICATION_BYPASS.isCritical()).isTrue();
    assertThat(StatusReport.FIDO_CERTIFIED.isCritical()).isFalse();
    assertThat(StatusReport.NOT_FIDO_CERTIFIED.isCritical()).isFalse();
  }
}
