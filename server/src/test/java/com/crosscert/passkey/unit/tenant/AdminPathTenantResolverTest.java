package com.crosscert.passkey.unit.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.resolver.AdminPathTenantResolver;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class AdminPathTenantResolverTest {

  private final AdminPathTenantResolver resolver = new AdminPathTenantResolver();

  @Test
  void resolves_tenant_id_from_admin_tenant_path() {
    UUID tenantId = UUID.fromString("12345678-1234-1234-1234-123456789abc");
    HttpServletRequest req = get("/api/v1/admin/tenants/" + tenantId + "/webauthn-config");

    Optional<TenantContext> ctx = resolver.resolve(req);

    assertThat(ctx).isPresent();
    assertThat(ctx.get().tenantId()).isEqualTo(tenantId);
  }

  @Test
  void resolves_tenant_id_from_admin_tenant_root_path() {
    UUID tenantId = UUID.randomUUID();
    HttpServletRequest req = get("/api/v1/admin/tenants/" + tenantId);

    Optional<TenantContext> ctx = resolver.resolve(req);

    assertThat(ctx).isPresent();
    assertThat(ctx.get().tenantId()).isEqualTo(tenantId);
  }

  @Test
  void resolves_nested_admin_endpoints() {
    UUID tenantId = UUID.randomUUID();
    HttpServletRequest req = get("/api/v1/admin/tenants/" + tenantId + "/credentials/abc/reassign");

    Optional<TenantContext> ctx = resolver.resolve(req);

    assertThat(ctx).isPresent();
    assertThat(ctx.get().tenantId()).isEqualTo(tenantId);
  }

  @Test
  void returns_empty_for_admin_tenants_list_path() {
    // /api/v1/admin/tenants (no id) → list endpoint, no tenant context.
    HttpServletRequest req = get("/api/v1/admin/tenants");

    assertThat(resolver.resolve(req)).isEmpty();
  }

  @Test
  void returns_empty_for_unrelated_paths() {
    assertThat(resolver.resolve(get("/api/v1/rp/passkeys/register/options"))).isEmpty();
    assertThat(resolver.resolve(get("/api/v1/admin/admins"))).isEmpty();
    assertThat(resolver.resolve(get("/api/v1/admin/system/mds/refresh"))).isEmpty();
    assertThat(resolver.resolve(get("/_diag/mds-status"))).isEmpty();
    assertThat(resolver.resolve(get("/"))).isEmpty();
  }

  @Test
  void returns_empty_when_uuid_is_malformed() {
    // The regex enforces 36 hex/hyphen chars but doesn't validate UUID semantics — UUID.fromString
    // is the final gate. A 36-char garbage string that still matches the regex must drop out.
    HttpServletRequest req =
        get("/api/v1/admin/tenants/zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz/credentials");

    assertThat(resolver.resolve(req)).isEmpty();
  }

  @Test
  void does_not_match_path_traversal_attempts() {
    assertThat(resolver.resolve(get("/api/v1/admin/tenants/..%2F..%2Fetc%2Fpasswd"))).isEmpty();
    assertThat(resolver.resolve(get("/api/v1/admin/tenants/../system/mds/refresh"))).isEmpty();
  }

  private static HttpServletRequest get(String uri) {
    MockHttpServletRequest req = new MockHttpServletRequest("GET", uri);
    req.setRequestURI(uri);
    return req;
  }
}
