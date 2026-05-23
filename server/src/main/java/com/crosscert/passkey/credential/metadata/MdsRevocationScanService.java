package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter.SuspendedRow;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Post-registration MDS revocation scan. One {@link #scan(MetadataBlob)} cycle:
 *
 * <ol>
 *   <li>Collect critical AAGUIDs (one {@link StatusReport} per entry — the first critical one).
 *   <li>If none, perform a lingering-token cleanup (covers a prior F5 between credential SUSPEND
 *       and refresh-token revoke) and return.
 *   <li>Otherwise: bulk SUSPEND via {@link CredentialAdminWriter}, then bulk revoke refresh tokens
 *       for the union of newly-suspended user-ids and any pre-existing lingering set, then write
 *       one audit row per affected tenant under that tenant's {@link TenantContext}.
 * </ol>
 *
 * <p>Gated on {@code passkey.admin.enabled=true} — same switch as {@link CredentialAdminWriter} /
 * {@link RefreshTokenAdminWriter}. {@code @ConditionalOnBean} was rejected for the same reason
 * {@code CredentialAdminWriter} avoids it (fragile when the depended-on bean is declared in the
 * same context refresh).
 *
 * <p>Metric naming follows the project convention (no {@code .total} suffix) — {@code
 * PrometheusMeterRegistry} appends {@code _total} to counters at export time. The previous spec
 * draft included {@code .total} on three counters; the code follows {@code CeremonyMetrics} /
 * {@code MdsDiagController} naming instead to avoid {@code _total_total} on the Prometheus side.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class MdsRevocationScanService {

  private final CredentialAdminWriter credentialAdminWriter;
  private final RefreshTokenAdminWriter refreshTokenAdminWriter;
  private final AuditService auditService;
  private final MeterRegistry meterRegistry;

  /**
   * Backing value for the {@code mds.scan.critical.aaguids} gauge. Registered once in the
   * constructor so the meter holds a strong reference — Micrometer's {@code MeterRegistry#gauge}
   * convenience overload wraps the value in a weak reference and silently turns into {@code NaN}
   * once the temporary number is GC'd. {@link AtomicInteger} both gives us the strong ref and
   * makes per-scan {@code .set(...)} thread-safe.
   */
  private final AtomicInteger criticalAaguidGauge = new AtomicInteger();

  public MdsRevocationScanService(
      CredentialAdminWriter credentialAdminWriter,
      RefreshTokenAdminWriter refreshTokenAdminWriter,
      AuditService auditService,
      MeterRegistry meterRegistry) {
    this.credentialAdminWriter = credentialAdminWriter;
    this.refreshTokenAdminWriter = refreshTokenAdminWriter;
    this.auditService = auditService;
    this.meterRegistry = meterRegistry;
    Gauge.builder("mds.scan.critical.aaguids", criticalAaguidGauge, AtomicInteger::doubleValue)
        .description("Number of critical AAGUIDs reported by the most recently scanned MDS BLOB")
        .register(meterRegistry);
  }

  /** Result summary of a single {@link #scan(MetadataBlob)} invocation. */
  public record ScanResult(
      long blobSerial, int credentialsAffected, int tokensRevoked, Set<UUID> tenantsAffected) {
    public static ScanResult empty(long blobSerial) {
      return new ScanResult(blobSerial, 0, 0, Set.of());
    }
  }

  /**
   * Run one revocation cycle for {@code blob}. Increments {@code mds.scan.runs{outcome}} and
   * stops the {@code mds.scan.duration} timer regardless of which branch ran.
   */
  public ScanResult scan(MetadataBlob blob) {
    Timer.Sample sample = Timer.start(meterRegistry);
    try {
      ScanResult result = doScan(blob);
      meterRegistry.counter("mds.scan.runs", "outcome", "success").increment();
      return result;
    } catch (RuntimeException e) {
      meterRegistry.counter("mds.scan.runs", "outcome", "failure").increment();
      throw e;
    } finally {
      sample.stop(meterRegistry.timer("mds.scan.duration"));
    }
  }

  private ScanResult doScan(MetadataBlob blob) {
    long blobSerial = blobSerialAsLong(blob);

    // 1) Collect critical AAGUIDs — first critical status per entry.
    Map<UUID, StatusReport> criticalAaguids = new LinkedHashMap<>();
    for (MetadataEntry e : blob.entries()) {
      if (e == null || e.aaguid() == null || e.statusReports() == null) {
        continue;
      }
      e.statusReports().stream()
          .filter(StatusReport::isCritical)
          .findFirst()
          .ifPresent(s -> criticalAaguids.putIfAbsent(e.aaguid(), s));
    }
    // Single gauge update point — reflects the latest BLOB's critical count for both branches
    // (set to 0 on an empty-critical BLOB so dashboards can alert on "gauge != 0" reliably).
    criticalAaguidGauge.set(criticalAaguids.size());
    log.info(
        "mds.scan.start critical={} blobSerial={}", criticalAaguids.size(), blobSerial);

    // 2) No criticals → lingering-token cleanup only (covers prior F5 between credential SUSPEND
    //    and refresh-token revoke). Task 12 retry-integration test exercises this branch.
    if (criticalAaguids.isEmpty()) {
      Set<UUID> lingering =
          credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken();
      if (lingering != null && !lingering.isEmpty()) {
        int revoked =
            refreshTokenAdminWriter.revokeAllByTenantUserIds(
                lingering, RevokedReason.CREDENTIAL_SUSPENDED);
        log.info(
            "mds.scan.tokens.lingering.revoked count={} users={}", revoked, lingering.size());
        meterRegistry.counter("mds.scan.tokens.revoked").increment(revoked);
      }
      return ScanResult.empty(blobSerial);
    }

    // 3) Bulk SUSPEND across tenants.
    long t0 = System.currentTimeMillis();
    List<SuspendedRow> newlySuspended =
        credentialAdminWriter.suspendByAaguids(criticalAaguids, blobSerial);
    log.info(
        "mds.scan.suspended.applied affected={} aaguidGroups={} elapsedMs={}",
        newlySuspended.size(),
        criticalAaguids.size(),
        System.currentTimeMillis() - t0);

    // 4) §5.2 — union of newly-suspended users and any pre-existing lingering set.
    Set<UUID> tenantUserIds = new HashSet<>();
    for (SuspendedRow r : newlySuspended) {
      tenantUserIds.add(r.tenantUserId());
    }
    Set<UUID> preExisting =
        credentialAdminWriter.tenantUserIdsWithSuspendedCredentialAndLiveToken();
    if (preExisting != null) {
      tenantUserIds.addAll(preExisting);
    }

    // 5) Bulk revoke refresh tokens.
    int tokensRevoked =
        refreshTokenAdminWriter.revokeAllByTenantUserIds(
            tenantUserIds, RevokedReason.CREDENTIAL_SUSPENDED);
    log.info(
        "mds.scan.tokens.revoked count={} users={}", tokensRevoked, tenantUserIds.size());

    // 6) Per-tenant audit row under that tenant's TenantContext.
    Map<UUID, List<SuspendedRow>> byTenant =
        newlySuspended.stream().collect(Collectors.groupingBy(SuspendedRow::tenantId));
    byTenant.forEach((tenantId, rows) -> writeAuditUnder(tenantId, rows, blobSerial));
    log.info("mds.scan.audit.appended tenants={}", byTenant.size());

    // 7) Metrics. Aggregate suspended count is the sum of the tagged series — no untagged
    //    duplicate counter (the previous .total companion was double-bookkeeping the same value).
    meterRegistry.counter("mds.scan.tokens.revoked").increment(tokensRevoked);
    Map<UUID, Long> perAaguid =
        newlySuspended.stream()
            .collect(Collectors.groupingBy(SuspendedRow::aaguid, Collectors.counting()));
    perAaguid.forEach(
        (aaguid, count) ->
            meterRegistry
                .counter(
                    "mds.scan.suspended",
                    "aaguid",
                    aaguid.toString(),
                    "reason",
                    criticalAaguids.get(aaguid).name())
                .increment(count));

    log.info(
        "mds.scan.done credentials={} tokens={} tenants={} blobSerial={}",
        newlySuspended.size(),
        tokensRevoked,
        byTenant.size(),
        blobSerial);

    return new ScanResult(
        blobSerial, newlySuspended.size(), tokensRevoked, byTenant.keySet());
  }

  /**
   * Append the per-tenant audit row under {@code tenantId}'s context. {@link AuditService#append}
   * pulls the tenant from {@link TenantContextHolder#required()}, so we must set/clear around the
   * call. {@code finally} guarantees the {@link ThreadLocal} doesn't leak even if append throws.
   */
  private void writeAuditUnder(UUID tenantId, List<SuspendedRow> rows, long blobSerial) {
    Set<String> aaguids =
        rows.stream()
            .map(r -> r.aaguid().toString())
            .collect(Collectors.toCollection(LinkedHashSet::new));
    Map<String, Object> payload =
        Map.of(
            "credentialsAffected", rows.size(),
            "aaguidsAffected", aaguids,
            "mdsBlobSerial", blobSerial);
    try {
      TenantContextHolder.set(new TenantContext(tenantId, "mds-scan:" + tenantId));
      auditService.append(
          AuditEventType.CREDENTIAL_AUTO_SUSPENDED,
          ActorType.SYSTEM,
          null,
          "MDS_SCAN",
          String.valueOf(blobSerial),
          payload);
    } finally {
      TenantContextHolder.clear();
    }
  }

  /**
   * {@link MetadataBlob#serialNumber()} returns {@link Integer} (nullable). Coerce to {@code long}
   * — null becomes {@code 0L}, matching the {@code 0}-default DB column when BLOB omits the field.
   */
  private static long blobSerialAsLong(MetadataBlob blob) {
    Integer s = blob.serialNumber();
    return s == null ? 0L : s.longValue();
  }
}
