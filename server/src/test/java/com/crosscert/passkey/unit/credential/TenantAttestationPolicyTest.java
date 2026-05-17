package com.crosscert.passkey.unit.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.AttestationMode;
import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import java.lang.reflect.Field;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Closes the AAGUID null/zero bypass (P0-3) + the syncable opt-out (P1-4). Reflection sets the
 * fields directly so the test does not depend on persistence wiring.
 */
class TenantAttestationPolicyTest {

  private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
  private static final UUID ZERO = new UUID(0L, 0L);
  private static final UUID REAL = UUID.fromString("22222222-2222-2222-2222-222222222222");

  @Test
  void null_aaguid_rejected_in_every_mode_when_allowZeroAaguid_false() {
    for (AttestationMode mode : AttestationMode.values()) {
      TenantAttestationPolicy p = build(mode, List.of(), List.of(), false, true);
      assertThat(p.accepts(null)).as("mode=%s null AAGUID should be rejected", mode).isFalse();
      assertThat(p.accepts(ZERO)).as("mode=%s zero AAGUID should be rejected", mode).isFalse();
    }
  }

  @Test
  void null_aaguid_accepted_when_allowZeroAaguid_true() {
    TenantAttestationPolicy p = build(AttestationMode.ANY, List.of(), List.of(), true, true);
    assertThat(p.accepts(null)).isTrue();
    assertThat(p.accepts(ZERO)).isTrue();
  }

  @Test
  void allowlist_requires_explicit_aaguid() {
    TenantAttestationPolicy allowReal =
        build(AttestationMode.ALLOWLIST, List.of(REAL.toString()), List.of(), false, true);
    assertThat(allowReal.accepts(REAL)).isTrue();
    assertThat(allowReal.accepts(UUID.randomUUID())).isFalse();
  }

  @Test
  void denylist_blocks_listed_aaguid() {
    TenantAttestationPolicy deny =
        build(AttestationMode.DENYLIST, List.of(), List.of(REAL.toString()), false, true);
    assertThat(deny.accepts(REAL)).isFalse();
    assertThat(deny.accepts(UUID.randomUUID())).isTrue();
  }

  @Test
  void any_mode_accepts_known_aaguid() {
    TenantAttestationPolicy any = build(AttestationMode.ANY, List.of(), List.of(), false, true);
    assertThat(any.accepts(REAL)).isTrue();
  }

  @Test
  void syncable_rejected_when_opt_out() {
    TenantAttestationPolicy strict = build(AttestationMode.ANY, List.of(), List.of(), true, false);
    assertThat(strict.acceptsSyncable(true)).isFalse();
    assertThat(strict.acceptsSyncable(false)).isTrue();
  }

  @Test
  void syncable_accepted_by_default() {
    TenantAttestationPolicy permissive = TenantAttestationPolicy.permissive(TENANT);
    assertThat(permissive.acceptsSyncable(true)).isTrue();
    assertThat(permissive.acceptsSyncable(false)).isTrue();
  }

  private static TenantAttestationPolicy build(
      AttestationMode mode,
      List<String> allowed,
      List<String> denied,
      boolean allowZero,
      boolean allowSyncable) {
    TenantAttestationPolicy p = TenantAttestationPolicy.permissive(TENANT);
    p.update(mode, allowed, denied, false, allowZero, allowSyncable);
    return p;
  }

  // Compile-time guard: catches accidental signature changes.
  @SuppressWarnings("unused")
  private static final Field G1 = lookup("allowZeroAaguid");

  @SuppressWarnings("unused")
  private static final Field G2 = lookup("allowSyncable");

  private static Field lookup(String name) {
    try {
      return TenantAttestationPolicy.class.getDeclaredField(name);
    } catch (NoSuchFieldException e) {
      throw new AssertionError(e);
    }
  }
}
