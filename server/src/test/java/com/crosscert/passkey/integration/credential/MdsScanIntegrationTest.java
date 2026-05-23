package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import io.micrometer.core.instrument.MeterRegistry;
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
 * End-to-end integration test for the MDS post-registration revocation pipeline.
 *
 * <p>Publishes an {@link MdsBlobRefreshedEvent} containing a critical AAGUID, lets the
 * {@code @Async} listener run on the {@code auditExecutor} pool, then asserts (a) cross-tenant
 * credentials with the critical AAGUID are SUSPENDED, (b) safe credentials remain ACTIVE, (c) live
 * refresh tokens for affected users are revoked, (d) per-tenant {@code CREDENTIAL_AUTO_SUSPENDED}
 * audit rows are written, and (e) the {@code mds.scan.suspended} counter increased.
 *
 * <p>Fixtures are seeded through the {@code APP_ADMIN} (VPD-exempt) data source — same pattern as
 * {@code CredentialAdminWriterSliceTest} / {@code RefreshTokenAdminWriterSliceTest} — so a single
 * connection can stage rows for both tenants without per-row {@link TenantSeed#withTenant} dancing.
 */
class MdsScanIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired TenantSeed seed;
  @Autowired ApplicationEventPublisher events;
  @Autowired MeterRegistry meterRegistry;

  @Autowired
  @Qualifier("adminDataSource")
  DataSource adminDataSource;

  private NamedParameterJdbcTemplate admin;

  @BeforeEach
  void setUp() {
    admin = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void scan_suspendsAffectedCredentials_acrossTenants_andRevokesAffectedTokens() {
    // ---- arrange ----
    UUID tenant1 = seed.createTenant("scan-it-1-" + UUID.randomUUID());
    UUID tenant2 = seed.createTenant("scan-it-2-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenant1, "user-a-" + UUID.randomUUID());
    UUID userB = seed.createUser(tenant1, "user-b-" + UUID.randomUUID());
    UUID userC = seed.createUser(tenant2, "user-c-" + UUID.randomUUID());

    UUID criticalAaguid = UUID.randomUUID();
    UUID safeAaguid = UUID.randomUUID();

    // Critical AAGUID: 2 ACTIVE credentials in tenant1 (userA, userB), 1 in tenant2 (userC).
    UUID credA1 = UUID.randomUUID();
    UUID credA2 = UUID.randomUUID();
    UUID credC = UUID.randomUUID();
    insertCredential(credA1, tenant1, userA, criticalAaguid, "ACTIVE");
    insertCredential(credA2, tenant1, userB, criticalAaguid, "ACTIVE");
    insertCredential(credC, tenant2, userC, criticalAaguid, "ACTIVE");
    // Safe AAGUID: 1 ACTIVE credential in tenant1 (userA).
    UUID credSafe = UUID.randomUUID();
    insertCredential(credSafe, tenant1, userA, safeAaguid, "ACTIVE");

    // userA in tenant1 has a live refresh token. After scan, MdsRevocationScanService should
    // revoke it because userA's credA1 is being suspended.
    UUID tokenA = UUID.randomUUID();
    insertLiveRefreshToken(tokenA, tenant1, userA);

    // Baseline metric: capture pre-scan sum of mds.scan.suspended counters.
    double suspendedBefore = sumSuspendedMetric();

    long blobSerial = System.nanoTime() & 0x7fffffff;
    MetadataBlob blob =
        newBlob(
            (int) blobSerial,
            List.of(
                entry(criticalAaguid, List.of(StatusReport.REVOKED)),
                entry(safeAaguid, List.of(StatusReport.FIDO_CERTIFIED))));

    // ---- act: publish the event; @Async listener picks it up on auditExecutor ----
    events.publishEvent(new MdsBlobRefreshedEvent(blob, Instant.now()));

    // ---- assert ----
    await()
        .atMost(15, TimeUnit.SECONDS)
        .pollInterval(200, TimeUnit.MILLISECONDS)
        .untilAsserted(
            () -> {
              // (a) Critical AAGUID credentials are SUSPENDED across both tenants.
              assertThat(statusOf(credA1)).isEqualTo("SUSPENDED");
              assertThat(statusOf(credA2)).isEqualTo("SUSPENDED");
              assertThat(statusOf(credC)).isEqualTo("SUSPENDED");

              // (b) Safe AAGUID credential is still ACTIVE.
              assertThat(statusOf(credSafe)).isEqualTo("ACTIVE");

              // (c) userA's live refresh token was revoked.
              assertThat(tokenRevokedReason(tokenA)).isEqualTo("CREDENTIAL_SUSPENDED");

              // (d) Per-tenant CREDENTIAL_AUTO_SUSPENDED audit row written for both tenants.
              assertThat(auditCount(tenant1, "CREDENTIAL_AUTO_SUSPENDED"))
                  .as("tenant1 audit row count")
                  .isGreaterThanOrEqualTo(1);
              assertThat(auditCount(tenant2, "CREDENTIAL_AUTO_SUSPENDED"))
                  .as("tenant2 audit row count")
                  .isGreaterThanOrEqualTo(1);

              // (e) mds.scan.suspended counter grew by at least 3 (3 newly suspended credentials).
              assertThat(sumSuspendedMetric() - suspendedBefore)
                  .as("mds.scan.suspended counter delta")
                  .isGreaterThanOrEqualTo(3.0);
            });

    // Verify the suspended_reason captured the MDS status name for forensics.
    String reasonA1 =
        admin.queryForObject(
            "SELECT suspended_reason FROM credential WHERE id = HEXTORAW(:id)",
            new MapSqlParameterSource("id", hex(credA1)),
            String.class);
    assertThat(reasonA1).isEqualTo("MDS_REVOKED:REVOKED");
  }

  // ---- helpers ----------------------------------------------------------------------------------

  private double sumSuspendedMetric() {
    return meterRegistry.find("mds.scan.suspended").counters().stream()
        .mapToDouble(c -> c.count())
        .sum();
  }

  private String statusOf(UUID credentialId) {
    return admin.queryForObject(
        "SELECT status FROM credential WHERE id = HEXTORAW(:id)",
        new MapSqlParameterSource("id", hex(credentialId)),
        String.class);
  }

  private String tokenRevokedReason(UUID tokenId) {
    return admin.queryForObject(
        "SELECT revoked_reason FROM refresh_token WHERE id = HEXTORAW(:id)",
        new MapSqlParameterSource("id", hex(tokenId)),
        String.class);
  }

  private int auditCount(UUID tenantId, String eventType) {
    Integer c =
        admin.queryForObject(
            "SELECT COUNT(*) FROM audit_log "
                + " WHERE tenant_id = HEXTORAW(:t) AND event_type = :et",
            new MapSqlParameterSource().addValue("t", hex(tenantId)).addValue("et", eventType),
            Integer.class);
    return c == null ? 0 : c;
  }

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
            .addValue("cid", "credId-" + id.toString().substring(0, 8))
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("agid", hex(aaguid))
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("st", status)
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

  private static MetadataEntry entry(UUID aaguid, List<StatusReport> statuses) {
    return new MetadataEntry(aaguid, List.of(), statuses);
  }

  /**
   * {@link MetadataBlob}'s constructor is private. Build one via reflection — same pattern as
   * {@code MdsRevocationScanServiceTest}.
   */
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
