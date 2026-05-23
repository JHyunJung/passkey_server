package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * End-to-end verification of the Task 11 PLATFORM_OPERATOR unsuspend endpoint.
 *
 * <p>Covers three scenarios:
 *
 * <ol>
 *   <li>Happy path — PO session restores SUSPENDED → ACTIVE, preserves {@code suspendedAt}/{@code
 *       suspendedReason}, sets {@code unsuspendedAt}/{@code unsuspendedBy}, writes a {@code
 *       CREDENTIAL_UNSUSPENDED} audit row.
 *   <li>Authorisation — RP_ADMIN session hitting the same endpoint must yield 403.
 *   <li>State guard — unsuspend on an ACTIVE credential yields 409 with code P017.
 * </ol>
 *
 * <p>Admin sessions are stubbed via {@code
 * SecurityMockMvcRequestPostProcessors.authentication(...)} so we do not have to drive the actual
 * form-login + CSRF dance. CSRF is still required on POSTs by the admin filter chain, so we attach
 * {@code csrf()} alongside the principal.
 */
@AutoConfigureMockMvc
class AdminUnsuspendIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired TenantSeed seed;
  @Autowired MockMvc mockMvc;
  @Autowired ObjectMapper objectMapper;

  @Autowired
  @Qualifier("adminDataSource")
  DataSource adminDataSource;

  private NamedParameterJdbcTemplate admin;

  @BeforeEach
  void setUp() {
    admin = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void unsuspend_byPlatformOperator_restoresActive_andAudits() throws Exception {
    UUID tenant = seed.createTenant("unsusp-po-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "user-" + UUID.randomUUID());
    UUID cred = UUID.randomUUID();
    insertSuspendedCredential(cred, tenant, user);

    UUID actorId = UUID.randomUUID();
    Authentication po = adminAuth(actorId, null, AdminRole.PLATFORM_OPERATOR);

    MvcResult result =
        mockMvc
            .perform(
                post(
                        "/api/v1/admin/tenants/{tenantId}/credentials/{credentialId}/unsuspend",
                        tenant,
                        cred)
                    .with(authentication(po))
                    .with(csrf()))
            .andExpect(status().isOk())
            .andReturn();

    JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
    assertThat(body.path("success").asBoolean()).isTrue();
    assertThat(body.path("data").path("status").asText()).isEqualTo("ACTIVE");

    // DB: status flipped to ACTIVE; suspendedAt/Reason preserved (forensics); unsuspended_at/by
    // set.
    MapSqlParameterSource p = new MapSqlParameterSource("id", hex(cred));
    String status =
        admin.queryForObject(
            "SELECT status FROM credential WHERE id = HEXTORAW(:id)", p, String.class);
    assertThat(status).isEqualTo("ACTIVE");

    String suspendedReason =
        admin.queryForObject(
            "SELECT suspended_reason FROM credential WHERE id = HEXTORAW(:id)", p, String.class);
    assertThat(suspendedReason).as("suspended_reason preserved").isEqualTo("MDS_REVOKED:REVOKED");

    OffsetDateTime suspendedAt =
        admin.queryForObject(
            "SELECT suspended_at FROM credential WHERE id = HEXTORAW(:id)",
            p,
            OffsetDateTime.class);
    assertThat(suspendedAt).as("suspended_at preserved").isNotNull();

    OffsetDateTime unsuspendedAt =
        admin.queryForObject(
            "SELECT unsuspended_at FROM credential WHERE id = HEXTORAW(:id)",
            p,
            OffsetDateTime.class);
    assertThat(unsuspendedAt).as("unsuspended_at set").isNotNull();

    String unsuspendedBy =
        admin.queryForObject(
            "SELECT unsuspended_by FROM credential WHERE id = HEXTORAW(:id)", p, String.class);
    assertThat(unsuspendedBy)
        .as("unsuspended_by carries the admin actor id")
        .isEqualTo(actorId.toString());

    // audit_log: one CREDENTIAL_UNSUSPENDED row for this tenant.
    Integer auditCount =
        admin.queryForObject(
            "SELECT COUNT(*) FROM audit_log "
                + " WHERE tenant_id = HEXTORAW(:t) "
                + "   AND event_type = 'CREDENTIAL_UNSUSPENDED' "
                + "   AND subject_id = :sid",
            new MapSqlParameterSource().addValue("t", hex(tenant)).addValue("sid", cred.toString()),
            Integer.class);
    assertThat(auditCount).isEqualTo(1);
  }

  @Test
  void unsuspend_byRpAdmin_isForbidden() throws Exception {
    UUID tenant = seed.createTenant("unsusp-rp-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "user-" + UUID.randomUUID());
    UUID cred = UUID.randomUUID();
    insertSuspendedCredential(cred, tenant, user);

    Authentication rpAdmin = adminAuth(UUID.randomUUID(), tenant, AdminRole.RP_ADMIN);

    mockMvc
        .perform(
            post(
                    "/api/v1/admin/tenants/{tenantId}/credentials/{credentialId}/unsuspend",
                    tenant,
                    cred)
                .with(authentication(rpAdmin))
                .with(csrf()))
        .andExpect(status().isForbidden());

    // DB unchanged.
    String stateAfter =
        admin.queryForObject(
            "SELECT status FROM credential WHERE id = HEXTORAW(:id)",
            new MapSqlParameterSource("id", hex(cred)),
            String.class);
    assertThat(stateAfter).isEqualTo("SUSPENDED");
  }

  @Test
  void unsuspend_onActiveCredential_yields409_P017() throws Exception {
    UUID tenant = seed.createTenant("unsusp-active-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "user-" + UUID.randomUUID());
    UUID cred = UUID.randomUUID();
    insertActiveCredential(cred, tenant, user);

    Authentication po = adminAuth(UUID.randomUUID(), null, AdminRole.PLATFORM_OPERATOR);

    mockMvc
        .perform(
            post(
                    "/api/v1/admin/tenants/{tenantId}/credentials/{credentialId}/unsuspend",
                    tenant,
                    cred)
                .with(authentication(po))
                .with(csrf()))
        .andExpect(status().isConflict())
        .andExpect(
            result -> {
              JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
              assertThat(body.path("code").asText()).isEqualTo("P017");
            });
  }

  // ---- helpers ----------------------------------------------------------------------------------

  private static Authentication adminAuth(UUID adminId, UUID tenantId, AdminRole role) {
    AdminPrincipal principal =
        new AdminPrincipal(adminId, tenantId, role, adminId + "@local", "Admin-" + adminId);
    return new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());
  }

  private void insertSuspendedCredential(UUID id, UUID tenantId, UUID userId) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO credential "
            + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, "
            + " user_handle, signature_counter, backup_eligible, backup_state, status, "
            + " suspended_at, suspended_reason, created_at, updated_at) VALUES ("
            + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, "
            + " :uh, 0, 0, 0, 'SUSPENDED', :now, :reason, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("cid", "cred-" + id.toString().substring(0, 8))
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("reason", "MDS_REVOKED:REVOKED")
            .addValue("now", now));
  }

  private void insertActiveCredential(UUID id, UUID tenantId, UUID userId) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO credential "
            + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, "
            + " user_handle, signature_counter, backup_eligible, backup_state, status, "
            + " created_at, updated_at) VALUES ("
            + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, "
            + " :uh, 0, 0, 0, 'ACTIVE', :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("cid", "cred-" + id.toString().substring(0, 8))
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("now", now));
  }

  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }
}
