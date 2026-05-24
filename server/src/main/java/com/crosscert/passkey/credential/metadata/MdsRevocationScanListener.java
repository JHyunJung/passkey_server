package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.audit.service.AuditAsyncConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Bridges {@link MdsBlobRefreshedEvent} → {@link MdsRevocationScanService} on the {@code
 * auditExecutor} thread pool. Fail-safe: exceptions are logged but never propagated to the event
 * publisher (refresh transaction must not depend on scan outcome).
 */
@Slf4j
@Component
@ConditionalOnBean(MdsRevocationScanService.class)
@RequiredArgsConstructor
public class MdsRevocationScanListener {

  private final MdsRevocationScanService scanService;

  @Async(AuditAsyncConfig.EXECUTOR_BEAN)
  @EventListener
  public void onBlobRefreshed(MdsBlobRefreshedEvent event) {
    try {
      scanService.scan(event.blob());
    } catch (Exception e) {
      log.error(
          "mds.revocation.scan.failed blobSerial={} reason={}",
          event.blob().serialNumber(),
          e.getMessage(),
          e);
    }
  }
}
