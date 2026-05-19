package com.crosscert.passkey.rp.client;

import com.crosscert.passkey.rp.dto.AuthenticationOptionsRequest;
import com.crosscert.passkey.rp.dto.AuthenticationOptionsResponse;
import com.crosscert.passkey.rp.dto.AuthenticationResult;
import com.crosscert.passkey.rp.dto.AuthenticationVerifyRequest;
import com.crosscert.passkey.rp.dto.CredentialView;
import com.crosscert.passkey.rp.dto.RefreshResult;
import com.crosscert.passkey.rp.dto.RegistrationBeginRequest;
import com.crosscert.passkey.rp.dto.RegistrationOptionsResponse;
import com.crosscert.passkey.rp.dto.RegistrationResult;
import com.crosscert.passkey.rp.dto.RegistrationVerifyRequest;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Multi-tenant variant. Caches one {@link DefaultPasskeyClient} per tenant UUID and lazy-creates
 * new ones via the supplied resolver. The resolver is consulted once per public method to pick the
 * active tenant; the resulting binding is reused by the underlying client for that call.
 */
public final class MultiTenantPasskeyClient implements PasskeyClient {

  private final PasskeyHttpClient http;
  private final ApiKeyResolver resolver;
  private final ConcurrentHashMap<UUID, DefaultPasskeyClient> perTenant = new ConcurrentHashMap<>();

  public MultiTenantPasskeyClient(PasskeyHttpClient http, ApiKeyResolver resolver) {
    this.http = http;
    this.resolver = resolver;
  }

  private DefaultPasskeyClient delegate(Object ctx) {
    ApiKeyResolver.TenantBinding b = resolver.resolve(ctx);
    return perTenant.computeIfAbsent(
        b.tenantId(), id -> new DefaultPasskeyClient(http, new BoundResolver(b)));
  }

  @Override
  public RegistrationOptionsResponse beginRegistration(RegistrationBeginRequest req, Object ctx) {
    return delegate(ctx).beginRegistration(req, ctx);
  }

  @Override
  public RegistrationResult finishRegistration(RegistrationVerifyRequest req, Object ctx) {
    return delegate(ctx).finishRegistration(req, ctx);
  }

  @Override
  public AuthenticationOptionsResponse beginAuthentication(
      AuthenticationOptionsRequest req, Object ctx) {
    return delegate(ctx).beginAuthentication(req, ctx);
  }

  @Override
  public AuthenticationResult finishAuthentication(AuthenticationVerifyRequest req, Object ctx) {
    return delegate(ctx).finishAuthentication(req, ctx);
  }

  @Override
  public List<CredentialView> listCredentials(String externalUserId, Object ctx) {
    return delegate(ctx).listCredentials(externalUserId, ctx);
  }

  @Override
  public CredentialView renameCredential(
      UUID id, String externalUserId, String nickname, Object ctx) {
    return delegate(ctx).renameCredential(id, externalUserId, nickname, ctx);
  }

  @Override
  public void deleteCredential(UUID id, String externalUserId, Object ctx) {
    delegate(ctx).deleteCredential(id, externalUserId, ctx);
  }

  @Override
  public RefreshResult refresh(String refreshToken, Object ctx) {
    return delegate(ctx).refresh(refreshToken, ctx);
  }

  /** Resolver that captures a single binding so per-tenant clients don't re-invoke the source. */
  private record BoundResolver(ApiKeyResolver.TenantBinding binding) implements ApiKeyResolver {
    @Override
    public TenantBinding resolve(Object requestContext) {
      return binding;
    }
  }
}
