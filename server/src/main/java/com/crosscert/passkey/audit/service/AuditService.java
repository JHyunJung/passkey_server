package com.crosscert.passkey.audit.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEntry;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.repository.AuditEntryRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
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
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
    String rowHash = sha256(prevHash + "|" + tenantId + "|" + eventType + "|" + payloadJson);

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
