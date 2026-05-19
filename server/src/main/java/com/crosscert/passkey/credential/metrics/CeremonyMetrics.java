package com.crosscert.passkey.credential.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.Getter;
import org.springframework.stereotype.Component;

@Getter
@Component
public class CeremonyMetrics {

  private final Counter registrationSuccess;
  private final Counter registrationFailure;
  private final Counter authenticationSuccess;
  private final Counter authenticationFailure;
  private final Counter signatureCounterRegression;

  /**
   * Counts BS-flag transitions of {@code false → true} (credential newly synced to cloud keychain).
   * Drives compliance dashboards that downgrade trust when consumer passkeys start syncing. The
   * opposite direction (UNSYNCED) is logged but not counted — it is not a security signal.
   */
  private final Counter backupStateSyncedFlips;

  /**
   * Within-tenant IDOR attempts: an RP requested rename/revoke for a credential that does not
   * belong to the supplied {@code externalUserId}. A sustained increase points at either a buggy RP
   * integration or a deliberate enumeration probe.
   */
  private final Counter ownershipMismatches;

  /**
   * Refresh-token rotate requests where the ambient {@code TenantContext} (decided by X-API-Key)
   * disagrees with the JWT {@code tid} claim. Indicates token exfil across tenants or a
   * confused-deputy bug on the RP side.
   */
  private final Counter tidMismatches;

  public CeremonyMetrics(MeterRegistry registry) {
    this.registrationSuccess =
        Counter.builder("passkey.registration").tag("outcome", "success").register(registry);
    this.registrationFailure =
        Counter.builder("passkey.registration").tag("outcome", "failure").register(registry);
    this.authenticationSuccess =
        Counter.builder("passkey.authentication").tag("outcome", "success").register(registry);
    this.authenticationFailure =
        Counter.builder("passkey.authentication").tag("outcome", "failure").register(registry);
    this.signatureCounterRegression =
        Counter.builder("passkey.signature_counter_regression").register(registry);
    this.backupStateSyncedFlips =
        Counter.builder("passkey.backup_state.flips").tag("direction", "synced").register(registry);
    this.ownershipMismatches =
        Counter.builder("passkey.security.ownership_mismatch").register(registry);
    this.tidMismatches =
        Counter.builder("passkey.security.refresh_tid_mismatch").register(registry);
  }
}
