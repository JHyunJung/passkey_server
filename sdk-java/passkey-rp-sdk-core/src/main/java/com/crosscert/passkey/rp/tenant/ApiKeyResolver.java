package com.crosscert.passkey.rp.tenant;

import java.util.UUID;

/**
 * Resolves which tenant — and therefore which API key — to use for a given request. RP integrations
 * either expose a single tenant via {@link FixedApiKeyResolver} or implement this SPI themselves
 * (subdomain-based, JWT-claim-based, etc.).
 *
 * <p>The {@link Object} request context is intentionally generic: the core module has no dependency
 * on jakarta.servlet, so the starter passes a {@code HttpServletRequest} while non-Spring callers
 * can pass anything that helps the resolver decide.
 */
public interface ApiKeyResolver {

  TenantBinding resolve(Object requestContext);

  record TenantBinding(UUID tenantId, String apiKey) {}
}
