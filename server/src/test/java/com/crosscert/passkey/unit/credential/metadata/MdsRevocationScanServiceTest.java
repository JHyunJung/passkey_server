package com.crosscert.passkey.unit.credential.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenAdminWriter;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanService;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanService.ScanResult;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter.SuspendedRow;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Constructor;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit coverage for the MDS revocation scan core. Verifies (a) the empty-critical lingering-cleanup
 * early-return path, (b) the full pipeline including per-tenant audit grouping, and (c) the
 * first-critical-status-per-entry collection rule.
 */
@ExtendWith(MockitoExtension.class)
class MdsRevocationScanServiceTest {

  @Mock private CredentialAdminWriter credentialAdminWriter;
  @Mock private RefreshTokenAdminWriter refreshTokenAdminWriter;
  @Mock private AuditService auditService;

  private SimpleMeterRegistry meterRegistry;
  private MdsRevocationScanService service;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    service =
        new MdsRevocationScanService(
            credentialAdminWriter, refreshTokenAdminWriter, auditService, meterRegistry);
  }

  // ---------- 1. no critical → lingering cleanup only -------------------------------------------

  @Test
  void scan_noCriticalEntries_executesLingeringCleanupOnly_withLingeringRevoke() {
    // BLOB has entries but no critical statuses (UPDATE_AVAILABLE is non-critical).
    MetadataBlob blob =
        blobOf(
            42,
            entry(UUID.randomUUID(), List.of(StatusReport.UPDATE_AVAILABLE)),
            entry(UUID.randomUUID(), List.of(StatusReport.FIDO_CERTIFIED_L2)));

    UUID lingeringUser = UUID.randomUUID();
    when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken())
        .thenReturn(Set.of(lingeringUser));
    when(refreshTokenAdminWriter.revokeAllByTenantUserIds(
            eq(Set.of(lingeringUser)), eq(RevokedReason.CREDENTIAL_SUSPENDED)))
        .thenReturn(2);

    ScanResult result = service.scan(blob);

    assertThat(result).isEqualTo(ScanResult.empty(42L));
    verify(credentialAdminWriter, never()).suspendByAaguids(any(), anyLong());
    verify(credentialAdminWriter, times(1)).tenantUserIdsWithSuspendedCredentialAndLiveToken();
    verify(refreshTokenAdminWriter, times(1))
        .revokeAllByTenantUserIds(
            eq(Set.of(lingeringUser)), eq(RevokedReason.CREDENTIAL_SUSPENDED));
    verifyNoInteractions(auditService);

    // tokens.revoked counter bumped by the lingering revoke count (no .total suffix — Prometheus
    // exporter appends _total on its own).
    assertThat(meterRegistry.counter("mds.scan.tokens.revoked").count()).isEqualTo(2.0);
    assertThat(meterRegistry.counter("mds.scan.runs", "outcome", "success").count()).isEqualTo(1.0);
    // critical.aaguids gauge reflects this BLOB's count — 0 here (no critical entries).
    Gauge criticalGauge = meterRegistry.find("mds.scan.critical.aaguids").gauge();
    assertThat(criticalGauge).isNotNull();
    assertThat(criticalGauge.value()).isEqualTo(0.0);
  }

  @Test
  void scan_noCriticalEntries_noLingering_skipsRevoke() {
    MetadataBlob blob = blobOf(7, entry(UUID.randomUUID(), List.of(StatusReport.FIDO_CERTIFIED)));

    when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken())
        .thenReturn(Set.of());

    ScanResult result = service.scan(blob);

    assertThat(result).isEqualTo(ScanResult.empty(7L));
    verify(credentialAdminWriter, never()).suspendByAaguids(any(), anyLong());
    verify(credentialAdminWriter, times(1)).tenantUserIdsWithSuspendedCredentialAndLiveToken();
    verify(refreshTokenAdminWriter, never()).revokeAllByTenantUserIds(any(), any());
    verifyNoInteractions(auditService);

    assertThat(meterRegistry.counter("mds.scan.tokens.revoked").count()).isEqualTo(0.0);
  }

  // ---------- 2. full pipeline + per-tenant audit -----------------------------------------------

  @Test
  void scan_criticalEntries_runFullPipeline_andAuditPerTenant() {
    UUID aaguidA = UUID.randomUUID();
    UUID aaguidB = UUID.randomUUID();
    MetadataBlob blob =
        blobOf(
            101,
            entry(aaguidA, List.of(StatusReport.REVOKED)),
            entry(aaguidB, List.of(StatusReport.ATTESTATION_KEY_COMPROMISE)));

    UUID tenant1 = UUID.randomUUID();
    UUID tenant2 = UUID.randomUUID();
    UUID user1 = UUID.randomUUID();
    UUID user2 = UUID.randomUUID();
    UUID user3 = UUID.randomUUID();

    // 3 newly-SUSPENDED rows: 2 under tenant1, 1 under tenant2.
    List<SuspendedRow> newlySuspended =
        List.of(
            new SuspendedRow(UUID.randomUUID(), tenant1, user1, aaguidA),
            new SuspendedRow(UUID.randomUUID(), tenant1, user2, aaguidB),
            new SuspendedRow(UUID.randomUUID(), tenant2, user3, aaguidA));
    when(credentialAdminWriter.suspendByAaguids(any(), eq(101L))).thenReturn(newlySuspended);
    when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken())
        .thenReturn(Set.of());
    when(refreshTokenAdminWriter.revokeAllByTenantUserIds(
            argThat(s -> s.containsAll(Set.of(user1, user2, user3)) && s.size() == 3),
            eq(RevokedReason.CREDENTIAL_SUSPENDED)))
        .thenReturn(5);

    ScanResult result = service.scan(blob);

    assertThat(result.blobSerial()).isEqualTo(101L);
    assertThat(result.credentialsAffected()).isEqualTo(3);
    assertThat(result.tokensRevoked()).isEqualTo(5);
    assertThat(result.tenantsAffected()).containsExactlyInAnyOrder(tenant1, tenant2);

    verify(credentialAdminWriter, times(1)).suspendByAaguids(any(), eq(101L));
    verify(refreshTokenAdminWriter, times(1))
        .revokeAllByTenantUserIds(any(), eq(RevokedReason.CREDENTIAL_SUSPENDED));

    // per-tenant audit: 2 tenants → 2 append calls
    verify(auditService, times(2))
        .append(
            eq(AuditEventType.CREDENTIAL_AUTO_SUSPENDED),
            eq(ActorType.SYSTEM),
            eq(null),
            eq("MDS_SCAN"),
            eq("101"),
            any());

    // metrics — aggregate suspended count is the sum of all tagged mds.scan.suspended series
    // (no separate untagged .total counter; that would have been duplicate bookkeeping).
    double suspendedTotal =
        meterRegistry.find("mds.scan.suspended").counters().stream()
            .mapToDouble(c -> c.count())
            .sum();
    assertThat(suspendedTotal).isEqualTo(3.0);
    assertThat(meterRegistry.counter("mds.scan.tokens.revoked").count()).isEqualTo(5.0);
    assertThat(meterRegistry.counter("mds.scan.runs", "outcome", "success").count()).isEqualTo(1.0);
    // per-AAGUID counter: aaguidA = 2 rows, aaguidB = 1 row
    assertThat(
            meterRegistry
                .counter("mds.scan.suspended", "aaguid", aaguidA.toString(), "reason", "REVOKED")
                .count())
        .isEqualTo(2.0);
    assertThat(
            meterRegistry
                .counter(
                    "mds.scan.suspended",
                    "aaguid",
                    aaguidB.toString(),
                    "reason",
                    "ATTESTATION_KEY_COMPROMISE")
                .count())
        .isEqualTo(1.0);
    // critical.aaguids gauge — 2 critical entries in this scenario
    Gauge criticalGauge = meterRegistry.find("mds.scan.critical.aaguids").gauge();
    assertThat(criticalGauge).isNotNull();
    assertThat(criticalGauge.value()).isEqualTo(2.0);
  }

  // ---------- 3. first critical status wins per entry -------------------------------------------

  @Test
  void scan_picksFirstCriticalReportPerEntry() {
    UUID aaguid = UUID.randomUUID();
    // Mixed status list: non-critical first, then a critical. Service must skip UPDATE_AVAILABLE
    // and select REVOKED into the criticalAaguids map.
    MetadataBlob blob =
        blobOf(55, entry(aaguid, List.of(StatusReport.UPDATE_AVAILABLE, StatusReport.REVOKED)));

    when(credentialAdminWriter.suspendByAaguids(any(), eq(55L))).thenReturn(List.of());
    when(credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken())
        .thenReturn(Set.of());
    when(refreshTokenAdminWriter.revokeAllByTenantUserIds(any(), any())).thenReturn(0);

    service.scan(blob);

    verify(credentialAdminWriter, times(1))
        .suspendByAaguids(
            argThat(
                (Map<UUID, StatusReport> m) ->
                    m != null && m.size() == 1 && m.get(aaguid) == StatusReport.REVOKED),
            eq(55L));
  }

  // ---------- helpers ---------------------------------------------------------------------------

  private static MetadataEntry entry(UUID aaguid, List<StatusReport> statuses) {
    return new MetadataEntry(aaguid, List.of(), statuses);
  }

  /**
   * {@link MetadataBlob} has a private constructor — production code only ever builds one via
   * {@link MetadataBlob#parse}. For unit-test scope we bypass parse() (no JWS) by invoking the
   * constructor reflectively. Keeps the production surface untouched.
   */
  private static MetadataBlob blobOf(int serial, MetadataEntry... entries) {
    try {
      Constructor<MetadataBlob> ctor =
          MetadataBlob.class.getDeclaredConstructor(List.class, String.class, Integer.class);
      ctor.setAccessible(true);
      return ctor.newInstance(List.of(entries), "2099-01-01", Integer.valueOf(serial));
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }
}
