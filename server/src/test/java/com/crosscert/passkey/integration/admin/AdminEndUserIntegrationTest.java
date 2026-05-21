package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.integration.support.IntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository.EndUserRow;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Integration test for {@link TenantUserRepository#findByTenantIdWithSearch} against the real
 * docker-compose Oracle. The slice test mocks repositories, so the LEFT JOIN aggregate, the
 * case-insensitive {@code q} filter, and the explicit GROUP BY {@code countQuery} are only verified
 * here.
 *
 * <p>Seeding follows the pattern from {@code TenantIsolationIntegrationTest}: tenants are inserted
 * via {@link TenantSeed#createTenant} (RLS-exempt table), and tenant-scoped rows ({@code
 * tenant_user}, {@code credential}) are inserted inside {@link TenantSeed#withTenant} so the VPD
 * context is set for the runtime DataSource.
 */
class AdminEndUserIntegrationTest extends IntegrationTestBase {

  @Autowired TenantSeed seed;
  @Autowired TenantUserRepository userRepo;
  @Autowired CredentialRepository credentialRepo;
  @Autowired TransactionTemplate tx;

  private UUID tenantAId;
  private UUID tenantBId;

  @BeforeEach
  void seedFixture() {
    tenantAId = seed.createTenant("a-" + UUID.randomUUID());
    tenantBId = seed.createTenant("b-" + UUID.randomUUID());

    // Tenant A: user a1 with 2 ACTIVE credentials.
    UUID a1Id = seed.createUser(tenantAId, "a1");
    seed.withTenant(
        tenantAId,
        () ->
            tx.executeWithoutResult(
                s -> {
                  credentialRepo.save(activeCredential(tenantAId, a1Id, "a1-cred-1"));
                  credentialRepo.save(activeCredential(tenantAId, a1Id, "a1-cred-2"));
                }));

    // Tenant A: user a2 with 1 ACTIVE + 1 REVOKED credential.
    UUID a2Id = seed.createUser(tenantAId, "a2");
    seed.withTenant(
        tenantAId,
        () ->
            tx.executeWithoutResult(
                s -> {
                  credentialRepo.save(activeCredential(tenantAId, a2Id, "a2-cred-active"));
                  Credential revoked = activeCredential(tenantAId, a2Id, "a2-cred-revoked");
                  revoked.revoke();
                  credentialRepo.save(revoked);
                }));

    // Tenant B: user b1 with displayName "Zoe" and 1 ACTIVE credential.
    UUID b1Id =
        seed.withTenant(
            tenantBId,
            () ->
                tx.execute(s -> userRepo.save(TenantUser.create(tenantBId, "b1", "Zoe")).getId()));
    seed.withTenant(
        tenantBId,
        () ->
            tx.executeWithoutResult(
                s -> credentialRepo.save(activeCredential(tenantBId, b1Id, "b1-cred-1"))));
  }

  @Test
  void list_counts_only_active_credentials_per_user() {
    Page<EndUserRow> page =
        seed.withTenant(
            tenantAId,
            () ->
                tx.execute(
                    s ->
                        userRepo.findByTenantIdWithSearch(tenantAId, null, PageRequest.of(0, 50))));

    assertThat(page.getContent())
        .filteredOn(r -> r.getExternalId().equals("a1"))
        .singleElement()
        .extracting(EndUserRow::getActiveCredentialCount)
        .isEqualTo(2L);

    // a2 has 1 ACTIVE + 1 REVOKED — the REVOKED credential must be excluded.
    assertThat(page.getContent())
        .filteredOn(r -> r.getExternalId().equals("a2"))
        .singleElement()
        .extracting(EndUserRow::getActiveCredentialCount)
        .isEqualTo(1L);
  }

  @Test
  void search_matches_external_id_and_display_name() {
    Page<EndUserRow> byExternalId =
        seed.withTenant(
            tenantAId,
            () ->
                tx.execute(
                    s ->
                        userRepo.findByTenantIdWithSearch(tenantAId, "a1", PageRequest.of(0, 50))));
    assertThat(byExternalId.getContent())
        .extracting(EndUserRow::getExternalId)
        .containsExactly("a1");

    // Case-insensitive match against displayName "Zoe" via the lowercased query "zoe".
    Page<EndUserRow> byDisplayName =
        seed.withTenant(
            tenantBId,
            () ->
                tx.execute(
                    s ->
                        userRepo.findByTenantIdWithSearch(
                            tenantBId, "zoe", PageRequest.of(0, 50))));
    assertThat(byDisplayName.getContent())
        .extracting(EndUserRow::getExternalId)
        .containsExactly("b1");
  }

  @Test
  void list_is_tenant_isolated() {
    Page<EndUserRow> page =
        seed.withTenant(
            tenantAId,
            () ->
                tx.execute(
                    s ->
                        userRepo.findByTenantIdWithSearch(tenantAId, null, PageRequest.of(0, 50))));

    assertThat(page.getContent())
        .extracting(EndUserRow::getExternalId)
        .containsExactlyInAnyOrder("a1", "a2")
        .doesNotContain("b1");
  }

  @Test
  void count_query_matches_filtered_total() {
    // The main query GROUP BYs; the explicit countQuery must still report the filtered user total.
    Page<EndUserRow> page =
        seed.withTenant(
            tenantAId,
            () ->
                tx.execute(
                    s ->
                        userRepo.findByTenantIdWithSearch(tenantAId, "a1", PageRequest.of(0, 50))));

    assertThat(page.getTotalElements()).isEqualTo(1L);
  }

  private static Credential activeCredential(
      UUID tenantId, UUID tenantUserId, String credentialId) {
    return Credential.create(
        tenantId,
        tenantUserId,
        credentialId,
        new byte[] {1, 2, 3},
        UUID.randomUUID(),
        "internal",
        "userHandle",
        0L,
        false,
        false);
  }
}
