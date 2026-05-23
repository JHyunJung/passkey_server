package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Verifies the RP-facing authentication-options endpoint filters {@code allowCredentials} to ACTIVE
 * credentials only — SUSPENDED and REVOKED entries are excluded (Task 10 contract).
 *
 * <p>The {@code X-Tenant-Id} header is used to drive the {@code HeaderTenantResolver} in the test
 * profile so the {@code ApiKeyAuthenticationFilter} pre-existing-context branch authorises the
 * request without an actual API key — the same dev/test bypass already documented on the resolver.
 */
@AutoConfigureMockMvc
class AuthenticationOptionsExcludesSuspendedTest extends AdminEnabledIntegrationTestBase {

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
  void options_returnsOnlyActiveCredentials_inAllowCredentials() throws Exception {
    UUID tenant = seed.createTenant("opts-it-" + UUID.randomUUID());
    String externalId = "user-" + UUID.randomUUID();
    UUID user = seed.createUser(tenant, externalId);
    insertWebauthnConfig(tenant);

    String credIdActive = "active-cred-" + UUID.randomUUID();
    String credIdSusp = "susp-cred-" + UUID.randomUUID();
    String credIdRev = "rev-cred-" + UUID.randomUUID();
    insertCredential(UUID.randomUUID(), tenant, user, credIdActive, "ACTIVE");
    insertCredential(UUID.randomUUID(), tenant, user, credIdSusp, "SUSPENDED");
    insertCredential(UUID.randomUUID(), tenant, user, credIdRev, "REVOKED");

    MvcResult result =
        mockMvc
            .perform(
                post("/api/v1/rp/passkeys/authenticate/options")
                    .header("X-Tenant-Id", tenant.toString())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"externalUserId\":\"" + externalId + "\"}"))
            .andExpect(status().isOk())
            .andReturn();

    JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
    JsonNode allow = body.path("data").path("allowCredentials");
    assertThat(allow.isArray()).as("allowCredentials must be an array").isTrue();

    List<String> ids = new ArrayList<>();
    allow.forEach(n -> ids.add(n.path("id").asText()));

    assertThat(ids).as("ACTIVE credential must be present").contains(credIdActive);
    assertThat(ids).as("SUSPENDED credential must be filtered out").doesNotContain(credIdSusp);
    assertThat(ids).as("REVOKED credential must be filtered out").doesNotContain(credIdRev);
  }

  // ---- helpers ----------------------------------------------------------------------------------

  private void insertWebauthnConfig(UUID tenantId) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO tenant_webauthn_config "
            + "(id, tenant_id, rp_id, rp_name, origins, timeout_ms, user_verification, "
            + " attestation_conveyance, resident_key, cred_protect, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), :rpid, :rpname, :origins, 60000, "
            + " 'PREFERRED', 'NONE', 'PREFERRED', 'NONE', :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(UUID.randomUUID()))
            .addValue("tid", hex(tenantId))
            .addValue("rpid", "example.com")
            .addValue("rpname", "Example RP")
            .addValue("origins", "https://example.com")
            .addValue("now", now));
  }

  private void insertCredential(
      UUID id, UUID tenantId, UUID userId, String credentialId, String status) {
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    MapSqlParameterSource params =
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("cid", credentialId)
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("st", status)
            .addValue("now", now);
    String sql;
    if ("SUSPENDED".equals(status)) {
      params.addValue("reason", "MDS_REVOKED:REVOKED");
      sql =
          "INSERT INTO credential "
              + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, "
              + " user_handle, signature_counter, backup_eligible, backup_state, status, "
              + " suspended_at, suspended_reason, created_at, updated_at) VALUES ("
              + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, "
              + " :uh, 0, 0, 0, :st, :now, :reason, :now, :now)";
    } else if ("REVOKED".equals(status)) {
      sql =
          "INSERT INTO credential "
              + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, "
              + " user_handle, signature_counter, backup_eligible, backup_state, status, "
              + " revoked_at, revoked_reason, created_at, updated_at) VALUES ("
              + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, "
              + " :uh, 0, 0, 0, :st, :now, 'ADMIN_FORCED', :now, :now)";
    } else {
      sql =
          "INSERT INTO credential "
              + "(id, tenant_id, tenant_user_id, credential_id, public_key_cose, "
              + " user_handle, signature_counter, backup_eligible, backup_state, status, "
              + " created_at, updated_at) VALUES ("
              + " HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :cid, :pk, "
              + " :uh, 0, 0, 0, :st, :now, :now)";
    }
    admin.update(sql, params);
  }

  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }
}
