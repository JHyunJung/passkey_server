package com.crosscert.passkey.unit.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Covers the {@link RefreshToken} state machine without spinning up Spring — issued → revoke /
 * expire / family-root logic. Wider integration (DB + TokenService rotation) is exercised via the
 * existing integration suite once V11 is applied.
 */
class RefreshTokenLifecycleTest {

  private static final UUID TENANT = UUID.randomUUID();
  private static final UUID USER = UUID.randomUUID();

  @Test
  void newly_issued_token_is_active() {
    RefreshToken t = newToken(null);
    assertThat(t.isActive()).isTrue();
    assertThat(t.isRevoked()).isFalse();
    assertThat(t.isExpired()).isFalse();
  }

  @Test
  void revoked_token_is_no_longer_active() {
    RefreshToken t = newToken(null);
    t.revoke(RevokedReason.USER_LOGOUT);
    assertThat(t.isRevoked()).isTrue();
    assertThat(t.isActive()).isFalse();
    assertThat(t.getRevokedReason()).isEqualTo(RevokedReason.USER_LOGOUT);
  }

  @Test
  void revoke_is_idempotent_and_preserves_first_reason() {
    RefreshToken t = newToken(null);
    t.revoke(RevokedReason.CREDENTIAL_REVOKED);
    OffsetDateTime firstRevoke = t.getRevokedAt();
    t.revoke(RevokedReason.USER_LOGOUT);
    assertThat(t.getRevokedReason()).isEqualTo(RevokedReason.CREDENTIAL_REVOKED);
    assertThat(t.getRevokedAt()).isEqualTo(firstRevoke);
  }

  @Test
  void rootJti_is_self_when_no_parent() {
    RefreshToken root = newToken(null);
    assertThat(root.rootJti()).isEqualTo(root.getId());
  }

  @Test
  void rootJti_is_parent_for_rotated_token() {
    RefreshToken root = newToken(null);
    RefreshToken child =
        RefreshToken.create(
            UUID.randomUUID(),
            TENANT,
            USER,
            root.getId(),
            OffsetDateTime.now(ZoneOffset.UTC).plusDays(30),
            "127.0.0.1",
            "ua");
    assertThat(child.rootJti()).isEqualTo(root.getId());
  }

  @Test
  void expired_token_is_inactive() {
    RefreshToken expired =
        RefreshToken.create(
            UUID.randomUUID(),
            TENANT,
            USER,
            null,
            OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(1),
            null,
            null);
    assertThat(expired.isExpired()).isTrue();
    assertThat(expired.isActive()).isFalse();
  }

  private static RefreshToken newToken(UUID parentJti) {
    return RefreshToken.create(
        UUID.randomUUID(),
        TENANT,
        USER,
        parentJti,
        OffsetDateTime.now(ZoneOffset.UTC).plusDays(30),
        "127.0.0.1",
        "test-ua");
  }
}
