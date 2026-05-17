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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Append-only audit logger with per-tenant SHA-256 hash chain.
 *
 * <p>{@code REQUIRES_NEW} ensures audit rows are durable even if the outer ceremony transaction
 * rolls back. {@code pg_advisory_xact_lock(hashtext(tenantId))} serialises {@code append} calls per
 * tenant inside Postgres so concurrent ceremonies cannot read the same {@code prev_hash} and fork
 * the chain.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

  private final AuditEntryRepository repo;
  private final ObjectMapper objectMapper;

  @PersistenceContext private EntityManager em;

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void append(
      AuditEventType eventType,
      ActorType actorType,
      String actorId,
      String subjectType,
      String subjectId,
      Map<String, Object> payload) {
    UUID tenantId = TenantContextHolder.required().tenantId();

    // Per-tenant serialisation. The advisory lock is released automatically at COMMIT/ROLLBACK.
    em.createNativeQuery("SELECT pg_advisory_xact_lock(hashtext(?1))")
        .setParameter(1, tenantId.toString())
        .getSingleResult();

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
            appendAsync(context, eventType, actorType, actorId, subjectType, subjectId, payload);
          }
        });
  }

  @Async("auditExecutor")
  public void appendAsync(
      TenantContext capturedContext,
      AuditEventType eventType,
      ActorType actorType,
      String actorId,
      String subjectType,
      String subjectId,
      Map<String, Object> payload) {
    try {
      TenantContextHolder.set(capturedContext);
      append(eventType, actorType, actorId, subjectType, subjectId, payload);
    } catch (RuntimeException ex) {
      // Audit write failed after the user-visible transaction already committed — surface it so
      // ops can reconcile. The integrity scheduler will flag any resulting chain gap.
      log.error(
          "audit.append.async.failed tenantId={} event={} actor={}:{} subject={}:{} reason={}",
          capturedContext.tenantId(),
          eventType,
          actorType,
          actorId,
          subjectType,
          subjectId,
          ex.toString());
    } finally {
      TenantContextHolder.clear();
    }
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
