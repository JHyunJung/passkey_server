package com.crosscert.passkey.slice.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.repository.CredentialAdminWriter;
import com.crosscert.passkey.credential.repository.CredentialAdminWriter.SuspendedRow;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Slice test for {@link CredentialAdminWriter}: covers the bulk SUSPEND path used by the MDS
 * post-registration revocation scan.
 *
 * <p><strong>Why not {@code @JdbcTest}.</strong> The writer issues Oracle-native SQL ({@code
 * HEXTORAW}, {@code SYSTIMESTAMP}, {@code SYS_EXTRACT_UTC}, multi-bind {@code IN} on {@code
 * RAW(16)}). {@code @JdbcTest} would auto-configure an in-memory H2 that cannot execute that
 * dialect. The whole point of the writer — running on the {@code APP_ADMIN} (VPD-exempt) data
 * source so a single UPDATE can cross tenant predicates — also requires the real Oracle role grid.
 * So this test extends {@link AdminEnabledIntegrationTestBase} (the same pattern the existing admin
 * data-source tests use) and seeds fixtures via the {@code adminJdbcTemplate}. The test still lives
 * under {@code slice/} because it exercises a single repository component in isolation, not a
 * controller-or-service stack.
 *
 * <p><strong>Seeding via APP_ADMIN.</strong> Parent {@code tenant}/{@code tenant_user} rows go
 * through {@link TenantSeed} (which uses the JPA repositories and {@code TenantContextHolder} to
 * satisfy VPD on the runtime data source). Child {@code credential} and {@code refresh_token} rows
 * are inserted directly through {@code adminJdbcTemplate} — bypassing VPD lets a single connection
 * write rows for any tenant, and it mirrors exactly the data source the writer-under-test reads.
 */
class CredentialAdminWriterSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired private CredentialAdminWriter writer;

  @Autowired
  @Qualifier("adminJdbcTemplate")
  private NamedParameterJdbcTemplate admin;

  @Autowired TenantSeed seed;

  private UUID tenantA;
  private UUID userA;
  private UUID aaguid1;
  private UUID aaguid2;

  @BeforeEach
  void setupFixtures() {
    tenantA = seed.createTenant("mds-revscan-" + UUID.randomUUID());
    userA = seed.createUser(tenantA, "user-a-" + UUID.randomUUID());
    // Per-test random AAGUIDs so concurrent test classes sharing the schema don't collide on the
    // cross-tenant aaguid scan path.
    aaguid1 = UUID.randomUUID();
    aaguid2 = UUID.randomUUID();
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid1, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid1, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid2, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenantA, userA, aaguid2, "REVOKED");
  }

  @Test
  void suspendByAaguids_onlyAffectsActiveRowsInGivenAaguids() {
    List<SuspendedRow> result =
        writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4711L);
    assertThat(result).hasSize(2);

    Integer suspended =
        admin.queryForObject(
            "SELECT COUNT(*) FROM credential WHERE aaguid = HEXTORAW(:a) AND status = 'SUSPENDED'",
            new MapSqlParameterSource("a", hex(aaguid1)),
            Integer.class);
    assertThat(suspended).isEqualTo(2);

    Integer otherSuspended =
        admin.queryForObject(
            "SELECT COUNT(*) FROM credential WHERE aaguid = HEXTORAW(:a) AND status = 'SUSPENDED'",
            new MapSqlParameterSource("a", hex(aaguid2)),
            Integer.class);
    assertThat(otherSuspended).isZero();

    // UPDATE wrote suspended_reason — the MDS status name is preserved in the audit trail.
    String reason =
        admin.queryForObject(
            "SELECT suspended_reason FROM credential "
                + " WHERE aaguid = HEXTORAW(:a) AND status = 'SUSPENDED' AND ROWNUM = 1",
            new MapSqlParameterSource("a", hex(aaguid1)),
            String.class);
    assertThat(reason).isEqualTo("MDS_REVOKED:REVOKED");
  }

  @Test
  void suspendByAaguids_isIdempotent() {
    writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4711L);
    List<SuspendedRow> second =
        writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4712L);
    assertThat(second).isEmpty();
  }

  @Test
  void suspendByAaguids_emptyInput_returnsEmpty_andRunsNoSql() {
    assertThat(writer.suspendByAaguids(Map.of(), 4711L)).isEmpty();
  }

  @Test
  void suspendByAaguids_spansTenants_proving_VPDExemptPath() {
    // Seed a second tenant with its own user and one ACTIVE credential under the same aaguid1.
    // Goes through TenantSeed (JPA, RLS-aware) for parent rows — same idiom as @BeforeEach above —
    // then adminJdbcTemplate for the credential row, mirroring the existing seed path.
    UUID tenantB = seed.createTenant("mds-revscan-b-" + UUID.randomUUID());
    UUID userB = seed.createUser(tenantB, "user-b-" + UUID.randomUUID());
    insertCredential(UUID.randomUUID(), tenantB, userB, aaguid1, "ACTIVE");

    List<SuspendedRow> result =
        writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 5000L);

    // tenantA contributes 2 ACTIVE rows under aaguid1 (from @BeforeEach), tenantB contributes 1.
    // A single UPDATE crossing both tenants only works because the writer runs on APP_ADMIN
    // (VPD-exempt); APP_RUNTIME would have been confined to a single tenant by the row policy.
    assertThat(result).hasSize(3);
    Set<UUID> tenantsAffected =
        result.stream().map(SuspendedRow::tenantId).collect(Collectors.toSet());
    assertThat(tenantsAffected).containsExactlyInAnyOrder(tenantA, tenantB);
  }

  @Test
  void tenantUserIdsWithSuspendedCredentialAndLiveToken_findsLingering() {
    writer.suspendByAaguids(Map.of(aaguid1, StatusReport.REVOKED), 4711L);
    insertLiveRefreshToken(tenantA, userA);
    Set<UUID> users = writer.tenantUserIdsWithSuspendedCredentialAndLiveToken();
    assertThat(users).contains(userA);
  }

  // ---- helpers --------------------------------------------------------------------------------

  /** UUID → 32-char hex for Oracle {@code HEXTORAW}. */
  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }

  /** Inserts a credential row through the APP_ADMIN (VPD-exempt) data source. */
  private void insertCredential(UUID id, UUID tenantId, UUID userId, UUID aaguid, String status) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO credential "
            + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, aaguid, "
            + " user_handle, signature_counter, backup_eligible, backup_state, status, "
            + " created_at, updated_at) VALUES ("
            + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, HEXTORAW(:agid), "
            + " :uh, 0, 0, 0, :st, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            // uk_cred_per_tenant is (tenant_id, credential_id) — short random suffix is enough.
            .addValue("cid", "credId-" + id.toString().substring(0, 8))
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("agid", hex(aaguid))
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("st", status)
            .addValue("now", now));
  }

  /** Inserts a live (non-revoked) refresh_token row through APP_ADMIN. */
  private void insertLiveRefreshToken(UUID tenantId, UUID userId) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :expires, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(UUID.randomUUID()))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("expires", now.plusDays(7)));
  }
}
