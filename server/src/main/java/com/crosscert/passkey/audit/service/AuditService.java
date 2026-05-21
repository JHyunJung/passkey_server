package com.crosscert.passkey.audit.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEntry;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.repository.AuditEntryRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Append-only audit logger with per-tenant SHA-256 hash chain.
 *
 * <p>{@code REQUIRES_NEW} ensures audit rows are durable even if the outer ceremony transaction
 * rolls back. Per-tenant serialisation is achieved via {@code DBMS_LOCK.ALLOCATE_UNIQUE} (one named
 * lock per tenant) plus {@code DBMS_LOCK.REQUEST} in eXclusive mode with {@code
 * release_on_commit=TRUE} — the Oracle equivalent of the previous {@code
 * pg_advisory_xact_lock(hashtext(tenantId))} pattern. Concurrent ceremonies for the same tenant
 * block on the same lock handle and therefore observe a consistent {@code prev_hash}.
 */
@Slf4j
@Service
public class AuditService {

  private final AuditEntryRepository repo;
  private final ObjectMapper objectMapper;

  /**
   * Off-thread writer for {@link #appendAfterCommit}. {@code @Lazy} breaks the AuditService ↔
   * AsyncAuditWriter constructor cycle ({@code AsyncAuditWriter} depends on {@code
   * AuditService#append}); the proxy is still a distinct bean, so {@code @Async} on {@link
   * AsyncAuditWriter#appendAsync} is honoured.
   */
  private final AsyncAuditWriter asyncAuditWriter;

  @PersistenceContext private EntityManager em;

  public AuditService(
      AuditEntryRepository repo,
      ObjectMapper objectMapper,
      @org.springframework.context.annotation.Lazy AsyncAuditWriter asyncAuditWriter) {
    this.repo = repo;
    this.objectMapper = objectMapper;
    this.asyncAuditWriter = asyncAuditWriter;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void append(
      AuditEventType eventType,
      ActorType actorType,
      String actorId,
      String subjectType,
      String subjectId,
      Map<String, Object> payload) {
    UUID tenantId = TenantContextHolder.required().tenantId();

    // Per-tenant serialisation. Lock handle is per-tenant ("passkey_audit_<uuid>"), so ceremonies
    // for different tenants do not contend. release_on_commit=TRUE means the lock is dropped at
    // the end of this @Transactional(REQUIRES_NEW) boundary — the Oracle counterpart to PG's
    // pg_advisory_xact_lock auto-release behavior.
    acquireTenantAuditLock(tenantId);

    String payloadJson;
    try {
      payloadJson = objectMapper.writeValueAsString(payload == null ? Map.of() : payload);
    } catch (JsonProcessingException e) {
      throw new BusinessException(
          ErrorCode.INTERNAL_SERVER_ERROR, "failed to serialise audit payload", e);
    }
    String prevHash = repo.findLatestForTenant(tenantId).map(AuditEntry::getRowHash).orElse("");
    String rowHash = computeRowHash(prevHash, tenantId, eventType, payloadJson);

    AuditEntry entry =
        new AuditEntry(
            UUID.randomUUID(),
            OffsetDateTime.now(ZoneOffset.UTC),
            tenantId,
            eventType,
            actorType,
            actorId,
            subjectType,
            subjectId,
            payloadJson,
            prevHash.isEmpty() ? null : prevHash,
            rowHash);
    repo.save(entry);
    log.debug(
        "audit.append tenantId={} event={} actor={}:{} subject={}:{} entryId={}",
        tenantId,
        eventType,
        actorType,
        actorId,
        subjectType,
        subjectId,
        entry.getId());
  }

  /**
   * Hot-path variant of {@link #append}: schedules the write to run on the {@code auditExecutor}
   * after the calling transaction commits. The advisory lock and hash chain semantics are unchanged
   * — they just happen off the ceremony's request thread. If the outer transaction rolls back, the
   * audit row is not written (matching the user-visible outcome).
   *
   * <p>Use only for ceremony success paths where audit latency on the response is undesirable.
   * Compliance-critical writes (signature counter regression, admin operations) should keep using
   * the synchronous {@link #append}.
   */
  public void appendAfterCommit(
      AuditEventType eventType,
      ActorType actorType,
      String actorId,
      String subjectType,
      String subjectId,
      Map<String, Object> payload) {
    // Capture tenant context now — the async thread does not inherit ThreadLocal state.
    TenantContext context = TenantContextHolder.required();
    if (!TransactionSynchronizationManager.isSynchronizationActive()) {
      // No active transaction → run synchronously to preserve durability semantics.
      append(eventType, actorType, actorId, subjectType, subjectId, payload);
      return;
    }
    TransactionSynchronizationManager.registerSynchronization(
        new TransactionSynchronization() {
          @Override
          public void afterCommit() {
            // Cross-bean call: AsyncAuditWriter is a separate proxied bean, so @Async actually
            // takes effect (a self-invocation would silently run inline on this thread).
            asyncAuditWriter.appendAsync(
                context, eventType, actorType, actorId, subjectType, subjectId, payload);
          }
        });
  }

  /**
   * Replays the SHA-256 hash chain for {@code tenantId} over the half-open interval {@code [from,
   * to)} and reports which rows (if any) no longer match. Read-only; safe to run against live
   * traffic. Caller must already hold the tenant context (admin endpoints use {@code
   * AdminAuthz.requireTenantAccess}; the scheduler iterates tenants explicitly).
   */
  @Transactional(readOnly = true)
  public ChainVerification verifyIntegrity(UUID tenantId, OffsetDateTime from, OffsetDateTime to) {
    String prev = "";
    long ok = 0;
    List<UUID> tampered = new ArrayList<>();
    try (Stream<AuditEntry> stream = repo.streamForTenantByTime(tenantId, from, to)) {
      for (AuditEntry e : (Iterable<AuditEntry>) stream::iterator) {
        String expected = computeRowHash(prev, tenantId, e.getEventType(), e.getPayload());
        String storedPrev = e.getPrevHash() == null ? "" : e.getPrevHash();
        boolean rowOk = expected.equals(e.getRowHash()) && Objects.equals(storedPrev, prev);
        if (rowOk) {
          ok++;
        } else {
          tampered.add(e.getId());
        }
        prev = e.getRowHash();
      }
    }
    return new ChainVerification(tenantId, from, to, ok, tampered);
  }

  /** Result of {@link #verifyIntegrity(UUID, OffsetDateTime, OffsetDateTime)}. */
  public record ChainVerification(
      UUID tenantId,
      OffsetDateTime from,
      OffsetDateTime to,
      long verifiedRows,
      List<UUID> tamperedEntryIds) {
    public boolean intact() {
      return tamperedEntryIds.isEmpty();
    }
  }

  /**
   * Per-tenant serialisation via Oracle DBMS_LOCK. ALLOCATE_UNIQUE turns the lockname into a
   * VARCHAR2 handle scoped to this session; REQUEST X_MODE (6) blocks competing sessions; timeout
   * 10s keeps a runaway ceremony from blocking other tenants' append calls indefinitely.
   *
   * <p>Implementation note: Hibernate's {@code createNativeQuery} does not bind OUT parameters on
   * arbitrary PL/SQL blocks, so we use {@link org.hibernate.Session#doWork(Work)} to run the
   * anonymous block as a JDBC {@link java.sql.CallableStatement} where we can register the OUT
   * parameter and read the return code directly.
   */
  private void acquireTenantAuditLock(UUID tenantId) {
    String lockName = "passkey_audit_" + tenantId;
    int rc =
        em.unwrap(org.hibernate.Session.class)
            .doReturningWork(
                connection -> {
                  String sql =
                      "DECLARE handle VARCHAR2(128); BEGIN "
                          + "DBMS_LOCK.ALLOCATE_UNIQUE(lockname => ?, lockhandle => handle); "
                          + "? := DBMS_LOCK.REQUEST("
                          + "  lockhandle => handle, lockmode => DBMS_LOCK.X_MODE, "
                          + "  timeout => 10, release_on_commit => TRUE); "
                          + "END;";
                  try (java.sql.CallableStatement cs = connection.prepareCall(sql)) {
                    cs.setString(1, lockName);
                    cs.registerOutParameter(2, java.sql.Types.INTEGER);
                    cs.execute();
                    return cs.getInt(2);
                  }
                });
    // rc: 0=success, 1=timeout, 2=deadlock, 3=parameter error, 4=already own lock,
    // 5=illegal handle. Accept 0 (acquired) and 4 (re-entrancy — same session).
    if (rc != 0 && rc != 4) {
      log.error("audit.lock.failed tenantId={} rc={}", tenantId, rc);
      throw new BusinessException(
          ErrorCode.INTERNAL_SERVER_ERROR, "audit lock acquisition failed rc=" + rc);
    }
  }

  private static String computeRowHash(
      String prevHash, UUID tenantId, AuditEventType eventType, String payloadJson) {
    return sha256(prevHash + "|" + tenantId + "|" + eventType + "|" + payloadJson);
  }

  private static String sha256(String input) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
