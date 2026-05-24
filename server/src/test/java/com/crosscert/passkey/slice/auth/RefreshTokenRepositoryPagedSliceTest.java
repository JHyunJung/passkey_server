package com.crosscert.passkey.slice.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.auth.jwt.domain.RefreshToken;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Slice test for the admin Sessions-tab repository hooks: paged listing of one user's refresh
 * tokens (active-only and all-states) plus an active-count aggregate. Exercised against the real
 * VPD-applied runtime data source so the queries are validated through Hibernate's Oracle dialect —
 * H2 would mask any divergence (e.g. {@code revoked_at IS NULL AND expires_at > :now} composition).
 *
 * <p>Seeding goes through {@link RefreshTokenSeed} on the admin (VPD-exempt) data source — the
 * existing {@code RefreshTokenAdminWriterSliceTest} already uses the same channel for its inline
 * inserts; the helper just promotes that pattern to a reusable bean.
 */
class RefreshTokenRepositoryPagedSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired RefreshTokenRepository repo;
  @Autowired TenantSeed seed;
  @Autowired RefreshTokenSeed tokenSeed;
  @Autowired TransactionTemplate tx;

  @Test
  void findActive_excludesExpiredAndRevoked() {
    UUID tenant = seed.createTenant("rt-active-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

    UUID activeId = tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertExpired(tenant, user, now.minusDays(1));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));

    Page<RefreshToken> page =
        seed.withTenant(
            tenant,
            () -> tx.execute(s -> repo.findActiveByTenantUserId(user, now, PageRequest.of(0, 10))));
    long activeCount =
        seed.withTenant(tenant, () -> tx.execute(s -> repo.countActiveByTenantUserId(user, now)));

    assertThat(page.getTotalElements()).isEqualTo(1L);
    assertThat(activeCount).isEqualTo(1L);
    assertThat(page.getContent()).extracting(RefreshToken::getId).containsExactly(activeId);
  }

  @Test
  void findAll_includesExpiredAndRevoked() {
    UUID tenant = seed.createTenant("rt-all-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

    tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertExpired(tenant, user, now.minusDays(1));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));

    Page<RefreshToken> page =
        seed.withTenant(
            tenant, () -> tx.execute(s -> repo.findAllByTenantUserId(user, PageRequest.of(0, 10))));

    assertThat(page.getTotalElements()).isEqualTo(3L);
  }
}
