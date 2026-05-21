package com.crosscert.passkey.slice.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AsyncAuditWriter;
import com.crosscert.passkey.audit.service.AuditAsyncConfig;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.tenant.context.TenantContext;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ContextConfiguration;

/**
 * Regression guard for the audit self-invocation bug: {@code AuditService.appendAfterCommit} used
 * to call {@code appendAsync} on {@code this}, so the Spring proxy never saw the call and
 * {@code @Async} was silently ignored — the write ran inline on the caller thread (post-commit,
 * with no transaction), failed VPD-closed, and ceremony-completion audit rows were lost.
 *
 * <p>{@link AsyncAuditWriter} is now a separate bean, so the call crosses a proxy boundary and
 * {@code @Async} actually takes effect. This test asserts the delegated write lands on an {@code
 * audit-*} executor thread rather than the calling thread. {@link AuditService} is mocked: the
 * concern here is purely the threading/proxy wiring, not hash-chain persistence.
 */
@SpringBootTest
@ContextConfiguration(classes = {AuditAsyncConfig.class, AsyncAuditWriter.class})
class AsyncAuditWriterSliceTest {

  @Autowired private AsyncAuditWriter writer;

  @MockBean private AuditService auditService;

  @Test
  void appendAsyncRunsOnAuditExecutorThreadNotCaller() {
    AtomicReference<String> executingThread = new AtomicReference<>();
    Mockito.doAnswer(
            inv -> {
              executingThread.set(Thread.currentThread().getName());
              return null;
            })
        .when(auditService)
        .append(
            ArgumentMatchers.any(),
            ArgumentMatchers.any(),
            ArgumentMatchers.any(),
            ArgumentMatchers.any(),
            ArgumentMatchers.any(),
            ArgumentMatchers.any());

    String callerThread = Thread.currentThread().getName();
    TenantContext ctx = new TenantContext(UUID.randomUUID(), "demo");

    writer.appendAsync(
        ctx,
        AuditEventType.CREDENTIAL_REGISTERED,
        ActorType.END_USER,
        "u",
        "CREDENTIAL",
        "c",
        Map.of());

    await()
        .atMost(Duration.ofSeconds(5))
        .untilAtomic(executingThread, org.hamcrest.Matchers.notNullValue());
    assertThat(executingThread.get())
        .as("audit write must run on the auditExecutor pool, not the caller thread")
        .startsWith("audit-")
        .isNotEqualTo(callerThread);
  }
}
