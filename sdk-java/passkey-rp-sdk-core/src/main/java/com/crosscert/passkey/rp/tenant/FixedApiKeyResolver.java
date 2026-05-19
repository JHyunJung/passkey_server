package com.crosscert.passkey.rp.tenant;

import java.util.UUID;

/** Single-tenant resolver — returns the same binding regardless of request context. */
public final class FixedApiKeyResolver implements ApiKeyResolver {

  private final TenantBinding binding;

  public FixedApiKeyResolver(UUID tenantId, String apiKey) {
    this.binding = new TenantBinding(tenantId, apiKey);
  }

  @Override
  public TenantBinding resolve(Object requestContext) {
    return binding;
  }
}
