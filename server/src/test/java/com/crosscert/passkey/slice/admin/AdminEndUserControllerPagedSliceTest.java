package com.crosscert.passkey.slice.admin;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.security.AdminPrincipal;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.CredentialSeed;
import com.crosscert.passkey.integration.support.RefreshTokenSeed;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Exercises the user-360 reshape: detail returns count-summary objects (no inline credentials),
 * with two new paged endpoints — credentials (with AAGUID label) and refresh-tokens (filterable by
 * status).
 *
 * <p>Boots the admin chain via {@link AdminEnabledIntegrationTestBase} and uses {@code
 * SecurityMockMvcRequestPostProcessors.authentication(...)} to stub the RP_ADMIN session — same
 * pattern as {@code AdminUnsuspendIntegrationTest}.
 */
@AutoConfigureMockMvc
class AdminEndUserControllerPagedSliceTest extends AdminEnabledIntegrationTestBase {

  @Autowired MockMvc mvc;
  @Autowired TenantSeed seed;
  @Autowired CredentialSeed credentialSeed;
  @Autowired RefreshTokenSeed tokenSeed;

  @Test
  void detail_returnsCountsObjectInsteadOfInlineCredentials() throws Exception {
    UUID tenant = seed.createTenant("d-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.SUSPENDED);
    tokenSeed.insertLive(tenant, user, OffsetDateTime.now(ZoneOffset.UTC).plusDays(7));

    mvc.perform(
            get("/api/v1/admin/tenants/{tid}/users/{uid}", tenant, user)
                .with(authentication(adminAuth(tenant))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.credentials.active").value(1))
        .andExpect(jsonPath("$.data.credentials.suspended").value(1))
        .andExpect(jsonPath("$.data.credentials.revoked").value(0))
        .andExpect(jsonPath("$.data.sessions.active").value(1))
        // OLD field should be gone — credentials[*] was a List, now is an object so [0] miss.
        .andExpect(jsonPath("$.data.credentials[0]").doesNotExist());
  }

  @Test
  void credentials_pagedReturnsAaguidLabel() throws Exception {
    UUID tenant = seed.createTenant("c-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);
    credentialSeed.create(tenant, user, CredentialStatus.ACTIVE);

    mvc.perform(
            get("/api/v1/admin/tenants/{tid}/users/{uid}/credentials?page=0&size=10", tenant, user)
                .with(authentication(adminAuth(tenant))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)))
        .andExpect(jsonPath("$.data.content[0].aaguid.aaguid").exists())
        .andExpect(jsonPath("$.data.content[0].aaguid.displayName").exists())
        .andExpect(jsonPath("$.data.content[0].aaguid.fromMds").isBoolean());
  }

  @Test
  void refreshTokens_defaultStatusActive_excludesRevoked() throws Exception {
    UUID tenant = seed.createTenant("t-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));

    mvc.perform(
            get(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens?page=0&size=10",
                    tenant,
                    user)
                .with(authentication(adminAuth(tenant))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(1)));
  }

  @Test
  void refreshTokens_statusAll_includesRevoked() throws Exception {
    UUID tenant = seed.createTenant("ta-" + UUID.randomUUID());
    UUID user = seed.createUser(tenant, "u-" + UUID.randomUUID());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    tokenSeed.insertLive(tenant, user, now.plusDays(7));
    tokenSeed.insertRevoked(tenant, user, now.plusDays(7));

    mvc.perform(
            get(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens"
                        + "?status=all&page=0&size=10",
                    tenant,
                    user)
                .with(authentication(adminAuth(tenant))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(2)));
  }

  private static Authentication adminAuth(UUID tenantId) {
    AdminPrincipal principal =
        new AdminPrincipal(UUID.randomUUID(), tenantId, AdminRole.RP_ADMIN, "ops@local", "Ops");
    return new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());
  }
}
