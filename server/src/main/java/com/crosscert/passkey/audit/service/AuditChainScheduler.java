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

  /** Singleton lease row in {@code scheduler_lease} reserving the verifier's leader slot. */
  private static final String VERIFIER_LEASE_NAME = "audit-chain-verifier";

  /** Cron: 03:30 UTC daily. Picked to avoid the 04:00 MDS refresh window. */
  @Scheduled(cron = "${passkey.audit.verify-cron:0 30 3 * * *}", zone = "UTC")
  @Transactional
  public void verifyAllTenantsDaily() {
    // Leader election across replicas: SELECT ... FOR UPDATE NOWAIT on a singleton lease row.
    // The first replica into the @Scheduled window holds the row lock until commit/rollback;
    // others observe ORA-00054 ("resource busy") and skip. SKIP LOCKED is not appropriate here
    // because we want a *definite* signal that the row is already held — NOWAIT gives that.
    try {
      em.createNativeQuery("SELECT name FROM scheduler_lease WHERE name = :name FOR UPDATE NOWAIT")
          .setParameter("name", VERIFIER_LEASE_NAME)
          .getSingleResult();
    } catch (RuntimeException ex) {
      // jakarta.persistence.PessimisticLockException, Spring's CannotAcquireLockException, and
      // ojdbc11's ORA-00054 wrapper all surface here. Distinguish by SQL state on the wrapped
      // SQLException — 61000 is the Oracle "resource busy" family used by NOWAIT.
      Throwable cause = ex;
      while (cause != null && !(cause instanceof java.sql.SQLException)) {
        cause = cause.getCause();
      }
      String sqlState = cause instanceof java.sql.SQLException sqlEx ? sqlEx.getSQLState() : null;
      if (sqlState != null && sqlState.startsWith("61")) {
        log.info("audit.chain.verify.skipped reason=another_replica_holds_lease");
        return;
      }
      throw ex;
    }
    em.createNativeQuery(
            "UPDATE scheduler_lease SET acquired_at = SYSTIMESTAMP, "
                + "holder = :holder WHERE name = :name")
        .setParameter("holder", java.net.InetAddress.getLoopbackAddress().getHostName())
        .setParameter("name", VERIFIER_LEASE_NAME)
        .executeUpdate();
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
}
