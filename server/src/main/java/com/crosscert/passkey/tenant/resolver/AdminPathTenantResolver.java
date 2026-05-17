package com.crosscert.passkey.tenant.resolver;

import com.crosscert.passkey.tenant.context.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Pulls {@code tenantId} from admin URLs shaped like {@code /api/v1/admin/tenants/{tenantId}/**}
 * and exposes it as the request's tenant context. Without this, Spring's {@code @Transactional}
 * interceptor opens a JDBC connection — and Hibernate's {@code MultiTenantConnectionProvider}
 * issues {@code SET LOCAL app.current_tenant = 'fail-closed'} — before the controller's {@code
 * AdminAuthz.requireTenantAccess(...)} call gets the chance to populate the holder. Any subsequent
 * {@code INSERT} into a tenant-scoped table then trips the RLS policy.
 *
 * <p>Ordered ahead of {@link HeaderTenantResolver} so an attacker can't override the URL tenant via
 * the {@code X-Tenant-Id} header on local/dev profiles. Authorisation is still enforced separately
 * by {@code AdminAuthz} inside each controller — this resolver is only about plumbing the RLS
 * context through the connection lifecycle.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AdminPathTenantResolver implements TenantResolver {

  private static final Pattern ADMIN_TENANT_PATH =
      Pattern.compile("^/api/v1/admin/tenants/([0-9a-fA-F\\-]{36})(?:/.*)?$");

  @Override
  public Optional<TenantContext> resolve(HttpServletRequest request) {
    String uri = request.getRequestURI();
    if (uri == null) {
      return Optional.empty();
    }
    Matcher m = ADMIN_TENANT_PATH.matcher(uri);
    if (!m.matches()) {
      return Optional.empty();
    }
    try {
      UUID tenantId = UUID.fromString(m.group(1));
      return Optional.of(new TenantContext(tenantId, "admin-path"));
    } catch (IllegalArgumentException ignored) {
      return Optional.empty();
    }
  }
}
