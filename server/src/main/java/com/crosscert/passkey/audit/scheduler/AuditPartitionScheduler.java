package com.crosscert.passkey.audit.scheduler;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.LocalDate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Calls {@code passkey.ensure_audit_log_partition(date)} every day so the next month's partition
 * exists long before the 1st-of-month rollover. Idempotent — the function does nothing when the
 * partition already exists, so running it on N instances is harmless even without coordination.
 *
 * <p>Without this, a quiet operator could miss the migration cron and the first INSERT on the 1st
 * of an uncovered month would fail with {@code no partition of relation "audit_log" found}, taking
 * out every ceremony write.
 */
@Slf4j
@Component
public class AuditPartitionScheduler {

  @PersistenceContext private EntityManager em;

  /** Run at 02:00 local time daily — well before the next-month boundary. */
  @Scheduled(cron = "${passkey.audit.partition-cron:0 0 2 * * *}")
  @Transactional
  public void ensureUpcomingPartitions() {
    try {
      ensure(LocalDate.now());
      ensure(LocalDate.now().plusMonths(1));
      ensure(LocalDate.now().plusMonths(2));
    } catch (RuntimeException ex) {
      log.error("audit.partition.ensure.failed reason={}", ex.getMessage(), ex);
    }
  }

  private void ensure(LocalDate target) {
    em.createNativeQuery("SELECT passkey.ensure_audit_log_partition(:target)")
        .setParameter("target", target)
        .getSingleResult();
    log.debug("audit.partition.ensured target={}", target);
  }
}
