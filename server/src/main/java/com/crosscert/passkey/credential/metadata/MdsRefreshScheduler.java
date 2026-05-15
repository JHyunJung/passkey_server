package com.crosscert.passkey.credential.metadata;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Periodically refreshes the FIDO MDS BLOB. Conditional on {@link MdsBlobProvider}, which itself is
 * gated by {@code passkey.mds.enabled=true} — so when MDS is off, this bean is not created and no
 * scheduled task runs.
 */
@Slf4j
@Component
@ConditionalOnBean(MdsBlobProvider.class)
@RequiredArgsConstructor
public class MdsRefreshScheduler {

  private final MdsBlobProvider provider;

  @Scheduled(cron = "${passkey.mds.refresh-cron:0 0 4 * * *}")
  public void scheduledRefresh() {
    try {
      provider.refresh();
    } catch (Exception e) {
      log.error("mds.scheduled.refresh.failed reason={}", e.getMessage(), e);
      // Stale BLOB is intentionally kept — strict tenants keep working on the last known good
      // metadata until the next successful refresh. They only fail-closed if the BLOB was never
      // fetched at all.
    }
  }
}
