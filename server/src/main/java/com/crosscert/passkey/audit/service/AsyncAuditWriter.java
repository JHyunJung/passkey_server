package com.crosscert.passkey.audit.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Off-request-thread audit writer for ceremony success paths.
 *
 * <p>Deliberately a separate bean from {@link AuditService}: {@code appendAfterCommit} schedules
 * this write from a {@code TransactionSynchronization.afterCommit()} callback, and it must cross a
 * Spring proxy boundary for {@link Async @Async} to take effect. When this lived as a method on
 * {@code AuditService} itself, {@code appendAfterCommit} called it via {@code this} — a
 * self-invocation the proxy never intercepts — so {@code @Async} was silently ignored: the write
 * ran inline on the caller thread, post-commit with no active transaction, hit the VPD fail-closed
 * path, and ceremony-completion audit rows were lost. Keeping it here forces the proxied call.
 *
 * <p>The async thread does not inherit the request thread's {@link TenantContextHolder}
 * ThreadLocal, so the tenant context is captured by the caller and re-bound here. The actual
 * persistence (advisory lock + hash chain + {@code REQUIRES_NEW} transaction) is delegated to
 * {@link AuditService#append} — another genuine cross-bean call, so {@code @Transactional} on
 * {@code append} is honoured too.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AsyncAuditWriter {

  private final AuditService auditService;

  /**
   * Persists one audit entry on the {@code auditExecutor} pool. Failures are logged (not rethrown):
   * the user-visible transaction has already committed, so there is nothing to roll back — the
   * integrity scheduler flags any resulting hash-chain gap.
   */
  @Async(AuditAsyncConfig.EXECUTOR_BEAN)
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
      auditService.append(eventType, actorType, actorId, subjectType, subjectId, payload);
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
}
