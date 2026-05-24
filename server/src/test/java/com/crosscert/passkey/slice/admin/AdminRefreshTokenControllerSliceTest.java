package com.crosscert.passkey.slice.admin;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
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

/**
 * Per-session revoke endpoint — DELETE on a single refresh-token id. Idempotent: re-revoking an
 * already-revoked token returns {@code alreadyRevoked=true} and does NOT emit a second audit row.
 *
 * <p>Boots the admin chain via {@link AdminEnabledIntegrationTestBase} and stubs the RP_ADMIN
 * session with {@code SecurityMockMvcRequestPostProcessors.authentication(...)} — same pattern as
 * {@code AdminEndUserControllerPagedSliceTest}.
 */
@AutoConfigureMockMvc
class AdminRefreshTokenControllerSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired MockMvc mvc;
  @Autowired TenantSeed seed;
  @Autowired RefreshTokenSeed tokenSeed;

  @Autowired
  @Qualifier("adminDataSource")
  DataSource adminDataSource;

  private NamedParameterJdbcTemplate admin;

  @BeforeEach
  void setUp() {
    admin = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void delete_revokesActive_returnsAlreadyRevokedFalse() throws Exception {
    UUID tenant = seed.createTenant("rd-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    UUID tokenId =
        tokenSeed.insertLive(tenant, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));

    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenant,
                    user,
                    tokenId)
                .with(authentication(adminAuthFor(tenant)))
                .with(csrf()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.alreadyRevoked").value(false));

    // Verify via the VPD-exempt admin JDBC since the runtime repository is tenant-scoped.
    OffsetDateTime revokedAt =
        admin.queryForObject(
            "SELECT revoked_at FROM refresh_token WHERE id = HEXTORAW(:id)",
            new MapSqlParameterSource("id", tokenId.toString().replace("-", "")),
            OffsetDateTime.class);
    org.assertj.core.api.Assertions.assertThat(revokedAt).as("revoked_at populated").isNotNull();

    String revokedReason =
        admin.queryForObject(
            "SELECT revoked_reason FROM refresh_token WHERE id = HEXTORAW(:id)",
            new MapSqlParameterSource("id", tokenId.toString().replace("-", "")),
            String.class);
    org.assertj.core.api.Assertions.assertThat(revokedReason).isEqualTo("ADMIN_FORCED");
  }

  @Test
  void delete_secondCallIsIdempotent_returnsAlreadyRevokedTrue() throws Exception {
    UUID tenant = seed.createTenant("idem-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    UUID tokenId =
        tokenSeed.insertRevoked(tenant, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));

    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenant,
                    user,
                    tokenId)
                .with(authentication(adminAuthFor(tenant)))
                .with(csrf()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.alreadyRevoked").value(true));
  }

  @Test
  void delete_tokenBelongsToDifferentUser_returns404() throws Exception {
    UUID tenant = seed.createTenant("mismatch-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenant, "ua-" + UUID.randomUUID());
    UUID userB = seed.createUser(tenant, "ub-" + UUID.randomUUID());
    UUID tokenOfA =
        tokenSeed.insertLive(tenant, userA, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));

    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenant,
                    userB,
                    tokenOfA)
                .with(authentication(adminAuthFor(tenant)))
                .with(csrf()))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("C003"));
  }

  @Test
  void delete_unknownToken_returns404() throws Exception {
    UUID tenant = seed.createTenant("u-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());

    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenant,
                    user,
                    UUID.randomUUID())
                .with(authentication(adminAuthFor(tenant)))
                .with(csrf()))
        .andExpect(status().isNotFound());
  }

  @Test
  void delete_wrongTenantAdmin_returns403() throws Exception {
    UUID tenantA = seed.createTenant("tA-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("tB-" + UUID.randomUUID());
    UUID user = seed.createUser(tenantA, "u-" + UUID.randomUUID());
    UUID tokenId =
        tokenSeed.insertLive(tenantA, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));

    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenantA,
                    user,
                    tokenId)
                .with(authentication(adminAuthFor(tenantB)))
                .with(csrf()))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("M002"));
  }

  private static Authentication adminAuthFor(UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, AdminRole.RP_ADMIN, "ops@local", "Ops");
    return new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());
  }
}
