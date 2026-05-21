package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.admin.service.AdminPlatformStatsService;
import com.crosscert.passkey.admin.service.AdminPlatformStatsService.PlatformStats;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.auth.apikey.domain.ApiKeyStatus;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Verifies {@link AdminPlatformStatsService#compute()} aggregates ACTIVE credentials, ACTIVE API
 * keys, and trailing-24h ceremony-start audit events <em>across multiple tenants</em>, against the
 * real docker-compose Oracle.
 *
 * <p><strong>Seeding approach.</strong> All seed rows for the three counted tables are inserted via
 * the {@code APP_ADMIN} {@link DataSource} (a fresh {@link NamedParameterJdbcTemplate} built here
 * on the {@code adminDataSource}). {@code APP_ADMIN} holds {@code EXEMPT ACCESS POLICY}, so VPD
 * never appends a tenant predicate — a single connection can therefore insert rows for two
 * different tenants without any {@code TenantContextHolder} juggling, and {@code api_key} (whose
 * {@code INSERT} grant is {@code APP_ADMIN}-only, see {@code ApiKeyAdminWriter}) is reachable on
 * the same path. The {@code tenant} parent rows still go through {@link TenantSeed} since that
 * table is RLS-exempt and the FK from all three tables points at it. This is the simplest reliable
 * path: one data source, one privilege level, no per-row context switching, and it mirrors exactly
 * the data source {@code AdminPlatformStatsService} itself reads from.
 *
 * <p>Each test seeds its own freshly-created tenant pair so the assertions are deltas, not absolute
 * counts — robust against the {@code tenant}/{@code admin_user} bootstrap rows and any residue from
 * other test classes sharing the schema.
 */
class AdminPlatformStatsIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired AdminPlatformStatsService statsService;
  @Autowired TenantSeed seed;

  @Autowired
  @Qualifier("adminDataSource")
  DataSource adminDataSource;

  private NamedParameterJdbcTemplate adminJdbc;

  @BeforeEach
  void setUp() {
    adminJdbc = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void aggregates_active_credentials_across_two_tenants() {
    PlatformStats before = statsService.compute();

    UUID tenantA = seed.createTenant("stats-cred-a-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("stats-cred-b-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenantA, "user-a");
    UUID userB = seed.createUser(tenantB, "user-b");

    // Tenant A: 2 ACTIVE credentials. Tenant B: 3 ACTIVE credentials.
    insertCredential(tenantA, userA, CredentialStatus.ACTIVE);
    insertCredential(tenantA, userA, CredentialStatus.ACTIVE);
    insertCredential(tenantB, userB, CredentialStatus.ACTIVE);
    insertCredential(tenantB, userB, CredentialStatus.ACTIVE);
    insertCredential(tenantB, userB, CredentialStatus.ACTIVE);

    PlatformStats after = statsService.compute();

    assertThat(after.activeCredentials() - before.activeCredentials())
        .as("ACTIVE credentials must be summed across tenant A (2) and tenant B (3)")
        .isEqualTo(5L);
  }

  @Test
  void revoked_credential_is_not_counted() {
    PlatformStats before = statsService.compute();

    UUID tenant = seed.createTenant("stats-cred-rev-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "user");

    insertCredential(tenant, user, CredentialStatus.ACTIVE);
    insertCredential(tenant, user, CredentialStatus.REVOKED);

    PlatformStats after = statsService.compute();

    assertThat(after.activeCredentials() - before.activeCredentials())
        .as("the REVOKED credential must be excluded — only the ACTIVE one counts")
        .isEqualTo(1L);
  }

  @Test
  void aggregates_active_api_keys_across_two_tenants() {
    PlatformStats before = statsService.compute();

    UUID tenantA = seed.createTenant("stats-key-a-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("stats-key-b-" + UUID.randomUUID());

    // Tenant A: 1 ACTIVE key. Tenant B: 2 ACTIVE keys + 1 REVOKED (must be excluded).
    insertApiKey(tenantA, ApiKeyStatus.ACTIVE);
    insertApiKey(tenantB, ApiKeyStatus.ACTIVE);
    insertApiKey(tenantB, ApiKeyStatus.ACTIVE);
    insertApiKey(tenantB, ApiKeyStatus.REVOKED);

    PlatformStats after = statsService.compute();

    assertThat(after.activeApiKeys() - before.activeApiKeys())
        .as("ACTIVE api_keys summed across tenants (1 + 2); the REVOKED key excluded")
        .isEqualTo(3L);
  }

  @Test
  void counts_only_ceremony_starts_within_24h_across_two_tenants() {
    PlatformStats before = statsService.compute();

    UUID tenantA = seed.createTenant("stats-cer-a-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("stats-cer-b-" + UUID.randomUUID());

    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

    // Tenant A: 1 registration-start within 24h, 1 stale (older than 24h → excluded).
    insertAuditEvent(tenantA, AuditEventType.REGISTRATION_OPTIONS_REQUESTED, now.minusHours(1));
    insertAuditEvent(tenantA, AuditEventType.REGISTRATION_OPTIONS_REQUESTED, now.minusHours(30));
    // Tenant B: 1 authentication-start within 24h, plus a non-ceremony event (excluded by type).
    insertAuditEvent(tenantB, AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED, now.minusHours(2));
    insertAuditEvent(tenantB, AuditEventType.CREDENTIAL_REGISTERED, now.minusHours(2));

    PlatformStats after = statsService.compute();

    assertThat(after.ceremonies24h() - before.ceremonies24h())
        .as(
            "only ceremony-start events inside the 24h window count, summed across tenants "
                + "(A=1, B=1); the stale event and the non-ceremony event are excluded")
        .isEqualTo(2L);
  }

  // --- seeding helpers (all via the APP_ADMIN, VPD-exempt data source) ---------------------

  private void insertCredential(UUID tenantId, UUID tenantUserId, CredentialStatus status) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    UUID id = UUID.randomUUID();
    adminJdbc.update(
        "INSERT INTO credential "
            + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, user_handle, "
            + " signature_counter, backup_eligible, backup_state, status, "
            + " revoked_at, revoked_reason, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tenantId), HEXTORAW(:tenantUserId), "
            + " :credentialId, :pk, :userHandle, 0, 0, 0, :status, "
            + " :revokedAt, :revokedReason, :createdAt, :updatedAt)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tenantId", hex(tenantId))
            .addValue("tenantUserId", hex(tenantUserId))
            .addValue("credentialId", "cred-" + id)
            .addValue("pk", new byte[] {1, 2, 3, 4})
            .addValue("userHandle", "uh-" + id)
            .addValue("status", status.name())
            .addValue("revokedAt", status == CredentialStatus.REVOKED ? now : null)
            .addValue("revokedReason", status == CredentialStatus.REVOKED ? "ADMIN_FORCED" : null)
            .addValue("createdAt", now)
            .addValue("updatedAt", now));
  }

  private void insertApiKey(UUID tenantId, ApiKeyStatus status) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    UUID id = UUID.randomUUID();
    adminJdbc.update(
        "INSERT INTO api_key "
            + "(id, tenant_id, prefix, secret_hash, name, status, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tenantId), :prefix, :secretHash, :name, "
            + " :status, :createdAt, :updatedAt)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tenantId", hex(tenantId))
            // prefix is globally UNIQUE (uk_api_key_prefix) — keep it short and random.
            .addValue("prefix", "pk_" + id.toString().substring(0, 8))
            .addValue("secretHash", "hash-" + id)
            .addValue("name", "key-" + id)
            .addValue("status", status.name())
            .addValue("createdAt", now)
            .addValue("updatedAt", now));
  }

  private void insertAuditEvent(UUID tenantId, AuditEventType eventType, OffsetDateTime createdAt) {
    UUID id = UUID.randomUUID();
    adminJdbc.update(
        "INSERT INTO audit_log "
            + "(id, tenant_id, event_type, actor_type, actor_id, row_hash, created_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tenantId), :eventType, :actorType, :actorId, "
            + " :rowHash, :createdAt)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tenantId", hex(tenantId))
            .addValue("eventType", eventType.name())
            .addValue("actorType", "SYSTEM")
            .addValue("actorId", "test")
            .addValue("rowHash", "hash-" + id)
            .addValue("createdAt", createdAt));
  }

  private static String hex(UUID id) {
    return id.toString().replace("-", "");
  }
}
