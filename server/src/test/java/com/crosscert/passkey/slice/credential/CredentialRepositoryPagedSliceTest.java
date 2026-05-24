package com.crosscert.passkey.slice.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.CredentialSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Slice test for the admin user-detail repository hooks: paged listing of one user's credentials
 * plus per-status count aggregates. Exercised against the real VPD-applied runtime data source so
 * both queries are validated through Hibernate's Oracle dialect (Spring Data's derived count needs
 * to compile to legal Oracle SQL — H2 would mask any divergence).
 */
class CredentialRepositoryPagedSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired CredentialRepository repo;
  @Autowired TenantSeed seed;
  @Autowired CredentialSeed credentialSeed;
  @Autowired TransactionTemplate tx;

  @Test
  void pagedByUser_returnsOnlyTargetUserRows() {
    UUID tenant = seed.createTenant("cred-page-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenant, "ua-" + UUID.randomUUID());
    UUID userB = seed.createUser(tenant, "ub-" + UUID.randomUUID());
    UUID c1 = credentialSeed.create(tenant, userA, CredentialStatus.ACTIVE);
    UUID c2 = credentialSeed.create(tenant, userA, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, userB, CredentialStatus.ACTIVE);

    Page<Credential> page =
        seed.withTenant(
            tenant,
            () -> tx.execute(s -> repo.findAllByTenantUserId(userA, PageRequest.of(0, 10))));

    assertThat(page.getTotalElements()).isEqualTo(2);
    assertThat(page.getContent()).extracting(Credential::getId).containsExactlyInAnyOrder(c1, c2);
  }

  @Test
  void countByUserAndStatus_perStatus() {
    UUID tenant = seed.createTenant("cred-count-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.SUSPENDED);
    credentialSeed.create(tenant, user, CredentialStatus.REVOKED);

    seed.withTenant(
        tenant,
        () ->
            tx.executeWithoutResult(
                s -> {
                  assertThat(repo.countByTenantUserIdAndStatus(user, CredentialStatus.ACTIVE))
                      .isEqualTo(2L);
                  assertThat(repo.countByTenantUserIdAndStatus(user, CredentialStatus.SUSPENDED))
                      .isEqualTo(1L);
                  assertThat(repo.countByTenantUserIdAndStatus(user, CredentialStatus.REVOKED))
                      .isEqualTo(1L);
                }));
  }
}
