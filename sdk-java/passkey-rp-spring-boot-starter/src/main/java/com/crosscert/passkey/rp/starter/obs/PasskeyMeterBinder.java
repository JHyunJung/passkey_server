package com.crosscert.passkey.rp.starter.obs;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;

/**
 * Registers the SDK's named counters so RP dashboards line up with the server's metric names. Hand
 * off to {@link MeterRegistry} once at startup; the filter and JWT verifier increment them at the
 * right spots.
 */
public class PasskeyMeterBinder implements MeterBinder {

  public static final String TID_MISMATCH = "passkey.security.tid_mismatch";
  public static final String JWT_VERIFY_FAILED = "passkey.security.jwt_verify_failed";
  public static final String REFRESH_REUSE = "passkey.security.refresh_reuse_detected";

  @Override
  public void bindTo(MeterRegistry registry) {
    Counter.builder(TID_MISMATCH).register(registry);
    Counter.builder(JWT_VERIFY_FAILED).register(registry);
    Counter.builder(REFRESH_REUSE).register(registry);
  }
}
