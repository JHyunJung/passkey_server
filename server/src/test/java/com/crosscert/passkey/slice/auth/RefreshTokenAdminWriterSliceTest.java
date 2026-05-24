package com.crosscert.passkey.slice.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenAdminWriter;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

/**
 * Slice test for {@link RefreshTokenAdminWriter}: covers the cross-tenant bulk revoke path used by
 * the MDS post-registration revocation scan (§5.2 token-cleanup boost).
 *
 * <p><strong>Why not {@code @JdbcTest}.</strong> Same reasoning as {@code
 * CredentialAdminWriterSliceTest}: the writer issues Oracle-native SQL ({@code HEXTORAW}, {@code
 * SYSTIMESTAMP}, {@code SYS_EXTRACT_UTC}, multi-bind {@code IN} on {@code RAW(16)}) and runs on the
 * {@code APP_ADMIN} (VPD-exempt) data source so a single UPDATE can cross tenants. So this test
 * extends {@link AdminEnabledIntegrationTestBase} and seeds fixtures via the {@code
 * adminJdbcTemplate}.
 */
class RefreshTokenAdminWriterSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired private RefreshTokenAdminWriter writer;

  @Autowired
  @Qualifier("adminJdbcTemplate")
  private NamedParameterJdbcTemplate admin;

  @Autowired TenantSeed seed;

  private UUID tenantA;
  private UUID userA;
  private UUID userB;

  @BeforeEach
  void setupFixtures() {
    tenantA = seed.createTenant("mds-rt-revscan-" + UUID.randomUUID());
    userA = seed.createUser(tenantA, "user-a-" + UUID.randomUUID());
    userB = seed.createUser(tenantA, "user-b-" + UUID.randomUUID());
  }

  @Test
  void revokeAllByTenantUserIds_empty_returnsZero_runsNoSql() {
    int n = writer.revokeAllByTenantUserIds(Set.of(), RevokedReason.CREDENTIAL_SUSPENDED);
    assertThat(n).isZero();
  }

  @Test
  void revokeAllByTenantUserIds_revokesOnlyLiveTokens_forSelectedUsers() {
    insertToken(tenantA, userA, null); // live, target
    insertToken(tenantA, userA, "ROTATED"); // already revoked → idempotent guard skips
    insertToken(tenantA, userB, null); // live, NOT in target set

    int n = writer.revokeAllByTenantUserIds(Set.of(userA), RevokedReason.CREDENTIAL_SUSPENDED);
    assertThat(n).isEqualTo(1);

    // userB's live token is still live — only the targeted user's tokens are touched.
    Integer liveOnB =
        admin.queryForObject(
            "SELECT COUNT(*) FROM refresh_token WHERE tenant_user_id = HEXTORAW(:u) AND revoked_at IS NULL",
            new MapSqlParameterSource("u", hex(userB)),
            Integer.class);
    assertThat(liveOnB).isEqualTo(1);

    // userA's previously-live token transitioned to CREDENTIAL_SUSPENDED.
    String reasonOnA =
        admin.queryForObject(
            "SELECT revoked_reason FROM refresh_token "
                + " WHERE tenant_user_id = HEXTORAW(:u) "
                + "   AND revoked_reason = 'CREDENTIAL_SUSPENDED' AND ROWNUM = 1",
            new MapSqlParameterSource("u", hex(userA)),
            String.class);
    assertThat(reasonOnA).isEqualTo("CREDENTIAL_SUSPENDED");

    // userA's already-ROTATED token is untouched (idempotent guard: WHERE revoked_at IS NULL).
    Integer rotatedOnA =
        admin.queryForObject(
            "SELECT COUNT(*) FROM refresh_token WHERE tenant_user_id = HEXTORAW(:u) AND revoked_reason = 'ROTATED'",
            new MapSqlParameterSource("u", hex(userA)),
            Integer.class);
    assertThat(rotatedOnA).isEqualTo(1);
  }

  /**
   * Oracle's 1000-expression IN-list cap (ORA-01795) is a real failure mode for an MDS scan that
   * suspends a wide AAGUID. Pass {@code CHUNK_SIZE + 100} distinct {@code tenant_user_id}s so the
   * writer is forced into &gt;1 chunk, and assert every live token transitioned — proving both that
   * no ORA-01795 was raised and that the chunked total is correct.
   */
  @Test
  void revokeAllByTenantUserIds_aboveChunkSize_chunksAndRevokesAll() {
    int n = RefreshTokenAdminWriter.CHUNK_SIZE + 100;
    LinkedHashSet<UUID> users = new LinkedHashSet<>(n);
    SqlParameterSource[] batch = new SqlParameterSource[n];
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    for (int i = 0; i < n; i++) {
      UUID uid = seed.createUser(tenantA, "bulk-" + i + "-" + UUID.randomUUID());
      users.add(uid);
      batch[i] =
          new MapSqlParameterSource()
              .addValue("id", hex(UUID.randomUUID()))
              .addValue("tid", hex(tenantA))
              .addValue("uid", hex(uid))
              .addValue("now", now)
              .addValue("expires", now.plusDays(7));
    }
    admin.batchUpdate(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :expires, :now, :now)",
        batch);

    int revoked = writer.revokeAllByTenantUserIds(users, RevokedReason.CREDENTIAL_SUSPENDED);

    assertThat(revoked).isEqualTo(n);
    Integer remainingLive =
        admin.queryForObject(
            "SELECT COUNT(*) FROM refresh_token WHERE tenant_id = HEXTORAW(:tid) AND revoked_at IS NULL",
            new MapSqlParameterSource("tid", hex(tenantA)),
            Integer.class);
    assertThat(remainingLive).isZero();
  }

  // ---- helpers --------------------------------------------------------------------------------

  /** UUID → 32-char hex for Oracle {@code HEXTORAW}. */
  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }

  /**
   * Inserts a refresh_token row through APP_ADMIN. If {@code revokedReason} is non-null, the row is
   * pre-revoked (used to seed the "already revoked, should be skipped" case).
   */
  private void insertToken(UUID tenantId, UUID userId, String revokedReason) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    MapSqlParameterSource p =
        new MapSqlParameterSource()
            .addValue("id", hex(UUID.randomUUID()))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("expires", now.plusDays(7));
    String sql;
    if (revokedReason == null) {
      sql =
          "INSERT INTO refresh_token "
              + "(id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
              + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :expires, :now, :now)";
    } else {
      p.addValue("rr", revokedReason);
      sql =
          "INSERT INTO refresh_token "
              + "(id, tenant_id, tenant_user_id, issued_at, expires_at, revoked_at, revoked_reason,"
              + " created_at, updated_at) "
              + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :expires, :now, :rr,"
              + " :now, :now)";
    }
    admin.update(sql, p);
  }
}
