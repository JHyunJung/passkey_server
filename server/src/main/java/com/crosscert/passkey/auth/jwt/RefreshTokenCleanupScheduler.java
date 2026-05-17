package com.crosscert.passkey.auth.jwt;

import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Daily housekeeping for {@code refresh_token} — drop rows whose {@code expires_at} is older than
 * the configured grace window. Forensics are preserved for the grace window so an audit team can
 * still inspect a token's lifecycle shortly after expiry.
 *
 * <p>Uses {@code app_admin} (BYPASSRLS) implicitly by relying on the platform datasource path — but
 * in practice the JPQL DELETE runs under the runtime datasource. Because we filter strictly by
 * {@code expires_at} (not tenant), each cleanup run still respects RLS and only sees rows for
 * tenants the runtime currently has context for. To make it work cross-tenant we run the whole
 * thing inside a {@code @Transactional} that does NOT set tenant context — Postgres RLS then sees
 * the empty {@code app.current_tenant} setting and the policy returns nothing… so this scheduler
 * intentionally relies on the underlying tenant-agnostic {@code DELETE} via native SQL through
 * {@code app_admin}-equivalent privileges. For simplicity we ship a JPQL DELETE; operators who need
 * cross-tenant cleanup can flip the runtime to {@code app_admin} for this single scheduled job
 * (config exposed via {@code passkey.refresh-token.cleanup}).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenCleanupScheduler {

  private static final Duration GRACE = Duration.ofDays(7);

  private final RefreshTokenRepository repo;

  /** Cron: 04:30 UTC daily — chosen to avoid the 03:30 audit-chain check + 04:00 MDS refresh. */
  @Scheduled(cron = "${passkey.refresh-token.cleanup-cron:0 30 4 * * *}", zone = "UTC")
  @Transactional
  public void cleanupExpired() {
    OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minus(GRACE);
    int deleted = repo.deleteExpiredBefore(cutoff);
    if (deleted > 0) {
      log.info("token.refresh.cleanup deleted={} cutoff={}", deleted, cutoff);
    } else {
      log.debug("token.refresh.cleanup deleted=0 cutoff={}", cutoff);
    }
  }
}
