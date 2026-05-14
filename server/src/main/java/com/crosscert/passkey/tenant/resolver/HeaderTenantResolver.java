package com.crosscert.passkey.tenant.resolver;

import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.service.TenantQueryService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Resolves tenant from the {@code X-Tenant-Id} header. Restricted to non-prod profiles — production
 * RP traffic uses {@code ApiKeyTenantResolver} (M3 BE-012). Reverse proxies must strip this header
 * before reaching prod.
 */
@Component
@Profile({"local", "test", "dev"})
@RequiredArgsConstructor
public class HeaderTenantResolver implements TenantResolver {

  public static final String HEADER = "X-Tenant-Id";

  private final TenantQueryService tenantQueryService;

  @Override
  public Optional<TenantContext> resolve(HttpServletRequest request) {
    String header = request.getHeader(HEADER);
    if (header == null || header.isBlank()) {
      return Optional.empty();
    }
    return tenantQueryService.findActive(header.trim());
  }
}
