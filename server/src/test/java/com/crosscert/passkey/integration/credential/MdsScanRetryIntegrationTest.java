package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.lang.reflect.Constructor;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Verifies the §5.2 lingering-token cleanup: a refresh BLOB with no critical AAGUIDs still revokes
 * live tokens whose owner already has a SUSPENDED credential (covers a prior F5 between the
 * credential SUSPEND commit and the refresh-token revoke commit).
 */
class MdsScanRetryIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired TenantSeed seed;
  @Autowired ApplicationEventPublisher events;

  @Autowired
  @Qualifier("adminDataSource")
  DataSource adminDataSource;

  private NamedParameterJdbcTemplate admin;

  @BeforeEach
  void setUp() {
    admin = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void scan_cleansUpLingeringTokens_evenWithNoCriticalAaguids() {
    UUID tenant = seed.createTenant("scan-retry-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "user-" + UUID.randomUUID());

    // Pre-seed: a SUSPENDED credential (simulating a prior scan that committed the suspend then
    // F5).
    UUID cred = UUID.randomUUID();
    insertSuspendedCredential(cred, tenant, user, UUID.randomUUID());

    // Pre-seed: a live refresh token that survived the F5 — this is what the lingering pass cleans.
    UUID token = UUID.randomUUID();
    insertLiveRefreshToken(token, tenant, user);

    // Empty critical-AAGUID BLOB. The lingering cleanup branch (no criticals → query
    // tenantUserIdsWithSuspendedCredentialAndLiveToken → bulk revoke) must still run.
    MetadataBlob empty = newBlob((int) (System.nanoTime() & 0x7fffffff), List.of());
    events.publishEvent(new MdsBlobRefreshedEvent(empty, Instant.now()));

    await()
        .atMost(15, TimeUnit.SECONDS)
        .pollInterval(200, TimeUnit.MILLISECONDS)
        .untilAsserted(
            () ->
                assertThat(tokenRevokedReason(token))
                    .as("lingering token must be revoked by the empty-critical scan path")
                    .isEqualTo("CREDENTIAL_SUSPENDED"));
  }

  // ---- helpers ----------------------------------------------------------------------------------

  private String tokenRevokedReason(UUID tokenId) {
    return admin.queryForObject(
        "SELECT revoked_reason FROM refresh_token WHERE id = HEXTORAW(:id)",
        new MapSqlParameterSource("id", hex(tokenId)),
        String.class);
  }

  private void insertSuspendedCredential(UUID id, UUID tenantId, UUID userId, UUID aaguid) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO credential "
            + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, aaguid, "
            + " user_handle, signature_counter, backup_eligible, backup_state, status, "
            + " suspended_at, suspended_reason, created_at, updated_at) VALUES ("
            + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, HEXTORAW(:agid), "
            + " :uh, 0, 0, 0, 'SUSPENDED', :now, :reason, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("cid", "credId-" + id.toString().substring(0, 8))
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("agid", hex(aaguid))
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("reason", "MDS_REVOKED:REVOKED")
            .addValue("now", now));
  }

  private void insertLiveRefreshToken(UUID tokenId, UUID tenantId, UUID userId) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :expires, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(tokenId))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("expires", now.plusDays(7)));
  }

  private static MetadataBlob newBlob(int serial, List<MetadataEntry> entries) {
    try {
      Constructor<MetadataBlob> ctor =
          MetadataBlob.class.getDeclaredConstructor(List.class, String.class, Integer.class);
      ctor.setAccessible(true);
      return ctor.newInstance(entries, "2099-01-01", Integer.valueOf(serial));
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }
}
