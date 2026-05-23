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
 * Verifies the RP-facing assertion verify endpoint rejects a SUSPENDED credential with HTTP 403
 * P016 — the Task 10 SUSPENDED-status branch in {@code
 * AuthenticationService.lookupActiveCredential} runs before signature verification, so we can
 * submit placeholder cryptographic material and still exercise the rejection path.
 *
 * <p>Flow: POST /options (consumes a real challenge into Redis) → POST /verify with the SUSPENDED
 * credential id + placeholder clientData/authenticatorData/signature. The verify endpoint pulls the
 * challenge by ceremonyId from Redis, then loads the credential, sees status=SUSPENDED, throws.
 */
@AutoConfigureMockMvc
class AssertionWithSuspendedCredentialIntegrationTest extends AdminEnabledIntegrationTestBase {

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
  void verify_onSuspendedCredential_returns403_P016() throws Exception {
    UUID tenant = seed.createTenant("verify-susp-" + UUID.randomUUID());
    String externalId = "user-" + UUID.randomUUID();
    UUID user = seed.createUser(tenant, externalId);
    insertWebauthnConfig(tenant);

    String suspendedCredId = "cred-susp-" + UUID.randomUUID();
    insertSuspendedCredential(UUID.randomUUID(), tenant, user, suspendedCredId);

    // Step 1: obtain a fresh ceremonyId by hitting /options. The endpoint stores the challenge in
    // Redis keyed by tenantId+ceremonyId; /verify will consume it via the same key. We pass the
    // user's externalId so the options call resolves the user (cosmetic — allowCredentials is
    // empty anyway because the only credential is SUSPENDED, but the ceremony still gets a
    // tenantUserId binding).
    MvcResult opts =
        mockMvc
            .perform(
                post("/api/v1/rp/passkeys/authenticate/options")
                    .header("X-Tenant-Id", tenant.toString())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"externalUserId\":\"" + externalId + "\"}"))
            .andExpect(status().isOk())
            .andReturn();
    JsonNode optsBody = objectMapper.readTree(opts.getResponse().getContentAsString());
    String ceremonyId = optsBody.path("data").path("ceremonyId").asText();
    assertThat(ceremonyId).isNotBlank();

    // Step 2: verify with the SUSPENDED credential id + placeholder cryptographic material.
    // The SUSPENDED-status check fires before signature verification (Task 10), so the dummy
    // bytes never get verified — we get a deterministic 403 P016 regardless of what we send.
    String verifyBody =
        "{"
            + "\"ceremonyId\":\""
            + ceremonyId
            + "\","
            + "\"credentialId\":\""
            + suspendedCredId
            + "\","
            + "\"clientDataJsonB64u\":\"placeholder\","
            + "\"authenticatorDataB64u\":\"placeholder\","
            + "\"signatureB64u\":\"placeholder\""
            + "}";
    mockMvc
        .perform(
            post("/api/v1/rp/passkeys/authenticate/verify")
                .header("X-Tenant-Id", tenant.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(verifyBody))
        .andExpect(status().isForbidden())
        .andExpect(
            result -> {
              JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
              assertThat(body.path("code").asText()).isEqualTo("P016");
            });
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

  private void insertSuspendedCredential(UUID id, UUID tenantId, UUID userId, String credentialId) {
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
            .addValue("cid", credentialId)
            .addValue("pk", new byte[] {1, 2, 3})
            .addValue("uh", "uh-" + userId.toString().substring(0, 8))
            .addValue("reason", "MDS_REVOKED:REVOKED")
            .addValue("now", now));
  }

  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }
}
