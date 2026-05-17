package com.crosscert.passkey.audit.service;

import com.crosscert.passkey.audit.service.AuditService.ChainVerification;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.Tenant;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Nightly self-check that replays the per-tenant audit hash chain over the previous 24 hours.
 * Tampered entries are surfaced via the {@code audit.chain.tampered} Micrometer counter (tagged
 * with {@code tenantId}) and ERROR-level logs so the on-call dashboard picks them up.
 *
 * <p>The scheduler iterates tenants explicitly and pushes each one into {@link TenantContextHolder}
 * so that RLS treats the read as in-scope (otherwise the runtime role would see zero rows). {@link
 * AuditService#verifyIntegrity} itself stays tenant-agnostic — it accepts the tenantId as an
 * argument.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditChainScheduler {

  private final TenantRepository tenantRepo;
  private final AuditService auditService;
  private final MeterRegistry meterRegistry;

  @PersistenceContext private EntityManager em;

  /** Stable advisory-lock key for the verifier — derived from a fixed string. */
  private static final long VERIFIER_LOCK_KEY = hash("passkey-audit-chain-verifier");

  /** Cron: 03:30 UTC daily. Picked to avoid the 04:00 MDS refresh window. */
  @Scheduled(cron = "${passkey.audit.verify-cron:0 30 3 * * *}", zone = "UTC")
  @Transactional(readOnly = true)
  public void verifyAllTenantsDaily() {
    // Leader election across replicas: pg_try_advisory_xact_lock is non-blocking and the lock is
    // released automatically on transaction commit/rollback. The first replica into the @Scheduled
    // window wins; the others log-and-skip instead of running the same verification N times.
    Boolean acquired =
        (Boolean)
            em.createNativeQuery("SELECT pg_try_advisory_xact_lock(?1)")
                .setParameter(1, VERIFIER_LOCK_KEY)
                .getSingleResult();
    if (acquired == null || !acquired) {
      log.info("audit.chain.verify.skipped reason=another_replica_is_running");
      return;
    }
    OffsetDateTime to = OffsetDateTime.now(ZoneOffset.UTC);
    OffsetDateTime from = to.minusDays(1);
    List<Tenant> tenants = tenantRepo.findAll();
    log.info("audit.chain.verify.start tenants={} from={} to={}", tenants.size(), from, to);
    long totalVerified = 0;
    long totalTampered = 0;
    for (Tenant tenant : tenants) {
      try {
        TenantContextHolder.set(
            new TenantContext(tenant.getId(), "audit-verifier:" + tenant.getId()));
        ChainVerification result = auditService.verifyIntegrity(tenant.getId(), from, to);
        totalVerified += result.verifiedRows();
        totalTampered += result.tamperedEntryIds().size();
        if (!result.intact()) {
          log.error(
              "audit.chain.tampered tenantId={} count={} ids={}",
              tenant.getId(),
              result.tamperedEntryIds().size(),
              result.tamperedEntryIds());
          Counter.builder("audit.chain.tampered")
              .tag("tenantId", tenant.getId().toString())
              .register(meterRegistry)
              .increment(result.tamperedEntryIds().size());
        }
      } catch (RuntimeException ex) {
        log.error("audit.chain.verify.error tenantId={} reason={}", tenant.getId(), ex.toString());
      } finally {
        TenantContextHolder.clear();
      }
    }
    log.info(
        "audit.chain.verify.done verified={} tampered={} tenants={}",
        totalVerified,
        totalTampered,
        tenants.size());
  }

  /**
   * Java's {@code String.hashCode} returns 32 bits; widen and mask to a stable 63-bit positive long
   * so the lock key is the same on every replica and never collides with Postgres' INT8 sign bit
   * when surfaced in {@code pg_locks}.
   */
  private static long hash(String s) {
    long h = 1125899906842597L; // prime seed
    for (int i = 0; i < s.length(); i++) {
      h = 31 * h + s.charAt(i);
    }
    return h & 0x7fffffffffffffffL;
  }
}
