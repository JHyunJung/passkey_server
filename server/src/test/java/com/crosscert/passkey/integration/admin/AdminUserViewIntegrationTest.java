package com.crosscert.passkey.integration.admin;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
import com.crosscert.passkey.integration.support.TestSupportConfig;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Full-path admin user-view exercise: list → detail → paged credentials → paged refresh-tokens →
 * single-token revoke → re-read → cross-tenant 403. Touches every endpoint added in Plan Tasks 8-9
 * + 10-11 + 12 in the order an operator would use them in real life.
 *
 * <p>Uses MockMvc + real Oracle VPD for tenant isolation verification.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(TestSupportConfig.class)
@ActiveProfiles("test")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class AdminUserViewIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired MockMvc mvc;
  @Autowired TenantSeed seed;
  @Autowired CredentialSeed credentialSeed;
  @Autowired RefreshTokenSeed tokenSeed;

  @Test
  void fullFlow_listDetailCredentialsTokensRevokeReread() throws Exception {
    // Setup: two tenants, each with users and credentials/tokens
    UUID tenantA = seed.createTenant("ivA-" + UUID.randomUUID());
    UUID tenantB = seed.createTenant("ivB-" + UUID.randomUUID());
    UUID userA = seed.createUser(tenantA, "alice-" + UUID.randomUUID());
    seed.createUser(tenantA, "bob-" + UUID.randomUUID());

    // Create credentials: 1 ACTIVE, 1 SUSPENDED
    credentialSeed.create(tenantA, userA, CredentialStatus.ACTIVE);
    credentialSeed.create(tenantA, userA, CredentialStatus.SUSPENDED);

    // Create refresh tokens: 2 ACTIVE (expires in future)
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    UUID activeToken = tokenSeed.insertLive(tenantA, userA, now.plusDays(7));
    tokenSeed.insertLive(tenantA, userA, now.plusDays(7));

    // 1) List users — paged, should see 2 users (alice + bob)
    mvc.perform(
            get("/api/v1/admin/tenants/{tid}/users?page=0&size=10", tenantA)
                .with(authentication(adminAuthFor(tenantA))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.content", hasSize(2)))
        .andExpect(jsonPath("$.data.totalElements").value(2));

    // 2) Detail — check credential and session counts without inline credentials
    mvc.perform(
            get("/api/v1/admin/tenants/{tid}/users/{uid}", tenantA, userA)
                .with(authentication(adminAuthFor(tenantA))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.externalId").exists())
        .andExpect(jsonPath("$.data.credentials.active").value(1))
        .andExpect(jsonPath("$.data.credentials.suspended").value(1))
        .andExpect(jsonPath("$.data.credentials.revoked").value(0))
        .andExpect(jsonPath("$.data.sessions.active").value(2));

    // 3) Credentials page — should list 2 credentials with AAGUID label + status
    mvc.perform(
            get(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/credentials?page=0&size=10",
                    tenantA,
                    userA)
                .with(authentication(adminAuthFor(tenantA))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.content", hasSize(2)))
        .andExpect(jsonPath("$.data.content[0].aaguid").exists())
        .andExpect(jsonPath("$.data.content[0].aaguid.fromMds").isBoolean())
        .andExpect(jsonPath("$.data.content[0].status").exists());

    // 4) Refresh-tokens page — default is active, so should see 2 tokens
    mvc.perform(
            get(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens?page=0&size=10",
                    tenantA,
                    userA)
                .with(authentication(adminAuthFor(tenantA))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.content", hasSize(2)))
        .andExpect(jsonPath("$.data.totalElements").value(2));

    // 5) Revoke one token — idempotency check via alreadyRevoked flag
    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenantA,
                    userA,
                    activeToken)
                .with(authentication(adminAuthFor(tenantA)))
                .with(csrf()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success").value(true))
        .andExpect(jsonPath("$.data.alreadyRevoked").value(false));

    // 6) Re-read active list — one less (1 active token remaining)
    mvc.perform(
            get(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens?page=0&size=10",
                    tenantA,
                    userA)
                .with(authentication(adminAuthFor(tenantA))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.content", hasSize(1)))
        .andExpect(jsonPath("$.data.totalElements").value(1));

    // 7) Idempotency — revoke same token again, alreadyRevoked=true
    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenantA,
                    userA,
                    activeToken)
                .with(authentication(adminAuthFor(tenantA)))
                .with(csrf()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.alreadyRevoked").value(true));

    // 8) Cross-tenant isolation — tenantB admin cannot read tenantA's user (403)
    mvc.perform(
            get("/api/v1/admin/tenants/{tid}/users/{uid}", tenantA, userA)
                .with(authentication(adminAuthFor(tenantB))))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.success").value(false))
        .andExpect(jsonPath("$.code").value("M002"));

    // 9) Cross-tenant token revoke also forbidden
    mvc.perform(
            delete(
                    "/api/v1/admin/tenants/{tid}/users/{uid}/refresh-tokens/{token}",
                    tenantA,
                    userA,
                    activeToken)
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
