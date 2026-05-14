package com.crosscert.passkey.auth.apikey.security;

import com.crosscert.passkey.auth.apikey.service.ApiKeyService.ResolvedKey;
import com.crosscert.passkey.tenant.context.TenantContext;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Authentication carrying the resolved API key + tenant. Built by {@link
 * ApiKeyAuthenticationFilter} after successful Argon2 verify.
 */
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

  private final ResolvedKey resolvedKey;
  private final TenantContext tenantContext;

  public ApiKeyAuthenticationToken(ResolvedKey resolvedKey, TenantContext tenantContext) {
    super(List.of(new SimpleGrantedAuthority("ROLE_RP_API")));
    this.resolvedKey = resolvedKey;
    this.tenantContext = tenantContext;
    setAuthenticated(true);
  }

  @Override
  public Object getCredentials() {
    return ""; // never expose the API key beyond verification
  }

  @Override
  public Object getPrincipal() {
    return resolvedKey;
  }

  public TenantContext tenantContext() {
    return tenantContext;
  }
}
