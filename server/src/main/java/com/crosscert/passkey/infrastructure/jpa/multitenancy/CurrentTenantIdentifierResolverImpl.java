package com.crosscert.passkey.infrastructure.jpa.multitenancy;

import com.crosscert.passkey.tenant.context.TenantContextHolder;
import org.hibernate.context.spi.CurrentTenantIdentifierResolver;
import org.springframework.stereotype.Component;

/**
 * Pulls the active tenant id from {@link TenantContextHolder}. When unset, returns a sentinel empty
 * string ({@link #UNSET}) rather than {@code null} — Hibernate 6.6+ rejects {@code null} tenant
 * identifiers in multi-tenant mode. The sentinel is bound as-is into {@code SET LOCAL
 * app.current_tenant}, and {@code passkey.current_tenant_id()} (defined in V1__baseline.sql)
 * applies {@code NULLIF} so empty string becomes SQL NULL, yielding zero rows under RLS
 * (fail-closed).
 */
@Component
public class CurrentTenantIdentifierResolverImpl
    implements CurrentTenantIdentifierResolver<String> {

  public static final String UNSET = "";

  @Override
  public String resolveCurrentTenantIdentifier() {
    return TenantContextHolder.optional().map(ctx -> ctx.tenantId().toString()).orElse(UNSET);
  }

  @Override
  public boolean validateExistingCurrentSessions() {
    return true;
  }
}
