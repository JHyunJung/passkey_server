package com.crosscert.passkey.auth.apikey.resolver;

import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.resolver.TenantResolver;
import com.crosscert.passkey.tenant.service.TenantQueryService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Resolves tenant from the {@code X-API-Key} header. Active in all profiles. Runs before {@code
 * HeaderTenantResolver} so production traffic uses API keys even when local dev profile is
 * accidentally combined.
 */
@Component
@Order(0)
@RequiredArgsConstructor
public class ApiKeyTenantResolver implements TenantResolver {

  public static final String HEADER = "X-API-Key";

  private final ApiKeyService apiKeyService;
  private final TenantQueryService tenantQueryService;

  @Override
  public Optional<TenantContext> resolve(HttpServletRequest request) {
    String header = request.getHeader(HEADER);
    if (header == null || header.isBlank()) {
      return Optional.empty();
    }
    return apiKeyService
        .verify(header.trim())
        .flatMap(rk -> tenantQueryService.findActive(rk.tenantId().toString()));
  }
}
