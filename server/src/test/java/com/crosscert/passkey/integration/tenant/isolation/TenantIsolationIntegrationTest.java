package com.crosscert.passkey.integration.tenant.isolation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.integration.support.IntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/** Proves RLS isolates tenant_user reads across tenants. */
class TenantIsolationIntegrationTest extends IntegrationTestBase {

  @Autowired TenantSeed seed;
  @Autowired TenantUserRepository userRepo;
  @Autowired TransactionTemplate tx;

  @Test
  void tenant_A_cannot_read_tenant_B_users() {
    UUID tenantA = seed.createTenant("aaa-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("bbb-" + UUID.randomUUID());
    seed.createUser(tenantA, "alice");
    seed.createUser(tenantB, "bob");

    seed.withTenant(
        tenantA,
        () -> {
          List<TenantUser> users = tx.execute(s -> userRepo.findAll());
          assertThat(users).extracting(TenantUser::getExternalId).containsExactly("alice");
        });

    seed.withTenant(
        tenantB,
        () -> {
          List<TenantUser> users = tx.execute(s -> userRepo.findAll());
          assertThat(users).extracting(TenantUser::getExternalId).containsExactly("bob");
        });
  }

  @Test
  void no_tenant_context_returns_zero_rows() {
    UUID tenantA = seed.createTenant("ccc-" + UUID.randomUUID());
    seed.createUser(tenantA, "alice");

    seed.withoutTenant(
        () -> {
          List<TenantUser> users = tx.execute(s -> userRepo.findAll());
          assertThat(users).isEmpty();
        });
  }
}
