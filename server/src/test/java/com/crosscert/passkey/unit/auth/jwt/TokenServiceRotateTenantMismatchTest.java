package com.crosscert.passkey.unit.auth.jwt;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.auth.jwt.JwtProperties;
import com.crosscert.passkey.auth.jwt.TokenPair;
import com.crosscert.passkey.auth.jwt.TokenService;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Defends against cross-tenant refresh: a refresh token issued under tenant A must not be
 * exchangeable under tenant B's API-key chain. Without this guard a leaked / exfiltrated refresh
 * token could be replayed by any other RP on the platform.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenServiceRotateTenantMismatchTest {

  @Mock private RefreshTokenRepository refreshRepo;
  private TokenService service;

  @BeforeEach
  void setUp() {
    JwtProperties props =
        new JwtProperties(
            "passkey-test",
            "0123456789abcdef0123456789abcdef", // 32 bytes, satisfies validator
            null,
            900L,
            2_592_000L);
    service =
        new TokenService(
            props, refreshRepo, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
  }

  @AfterEach
  void clearContext() {
    TenantContextHolder.clear();
  }

  @Test
  void rotate_rejects_when_ambient_tenant_differs_from_token_tid() {
    UUID tenantA = UUID.randomUUID();
    UUID tenantB = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    // Issue a token under tenant A (no ambient context yet → free to issue any tid).
    TokenPair issued = service.issue(tenantA, userId, "alice");

    // Now switch ambient context to tenant B and attempt rotate.
    TenantContextHolder.set(new TenantContext(tenantB, "tenant-b"));

    assertThatThrownBy(() -> service.rotate(issued.refreshToken(), "1.2.3.4", "ua"))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.INVALID_TOKEN);

    // The DB must not be touched once the tid check fails — otherwise an attacker could probe
    // refresh-token revocation state by timing the rotate call.
    verify(refreshRepo, never()).findByIdAndTenantUserId(any(), any());
  }

  @Test
  void rotate_proceeds_when_ambient_tenant_matches_token_tid() {
    UUID tenantA = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    TokenPair issued = service.issue(tenantA, userId, "alice");
    TenantContextHolder.set(new TenantContext(tenantA, "tenant-a"));

    // findByIdAndTenantUserId returns empty → we still throw, but the DB WAS hit, proving the
    // tid check passed (the empty-row branch is unrelated and exercised elsewhere).
    when(refreshRepo.findByIdAndTenantUserId(any(UUID.class), eq(userId)))
        .thenReturn(java.util.Optional.empty());

    assertThatThrownBy(() -> service.rotate(issued.refreshToken(), "1.2.3.4", "ua"))
        .isInstanceOf(BusinessException.class)
        .extracting(e -> ((BusinessException) e).getErrorCode())
        .isEqualTo(ErrorCode.REFRESH_TOKEN_REVOKED);

    verify(refreshRepo).findByIdAndTenantUserId(any(UUID.class), eq(userId));
  }
}
