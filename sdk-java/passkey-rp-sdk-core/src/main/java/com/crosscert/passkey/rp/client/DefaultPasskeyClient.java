package com.crosscert.passkey.rp.client;

import com.crosscert.passkey.rp.dto.AuthenticationOptionsRequest;
import com.crosscert.passkey.rp.dto.AuthenticationOptionsResponse;
import com.crosscert.passkey.rp.dto.AuthenticationResult;
import com.crosscert.passkey.rp.dto.AuthenticationVerifyRequest;
import com.crosscert.passkey.rp.dto.CredentialView;
import com.crosscert.passkey.rp.dto.RefreshRequest;
import com.crosscert.passkey.rp.dto.RefreshResult;
import com.crosscert.passkey.rp.dto.RegistrationBeginRequest;
import com.crosscert.passkey.rp.dto.RegistrationOptionsResponse;
import com.crosscert.passkey.rp.dto.RegistrationResult;
import com.crosscert.passkey.rp.dto.RegistrationVerifyRequest;
import com.crosscert.passkey.rp.dto.RpCredentialRenameRequest;
import com.crosscert.passkey.rp.tenant.ApiKeyResolver;
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The standard {@link PasskeyClient}. Maps every interface method to its server endpoint and
 * resolves the API key for each call via the injected {@link ApiKeyResolver}. Single-tenant
 * deployments inject {@link com.crosscert.passkey.rp.tenant.FixedApiKeyResolver}; multi-tenant
 * deployments provide their own resolver.
 */
public final class DefaultPasskeyClient implements PasskeyClient {

  private static final String REGISTER_OPTIONS = "/api/v1/rp/passkeys/register/options";
  private static final String REGISTER_VERIFY = "/api/v1/rp/passkeys/register/verify";
  private static final String AUTH_OPTIONS = "/api/v1/rp/passkeys/authenticate/options";
  private static final String AUTH_VERIFY = "/api/v1/rp/passkeys/authenticate/verify";
  private static final String CREDENTIALS = "/api/v1/rp/passkeys";
  private static final String REFRESH = "/api/v1/rp/auth/refresh";

  private final PasskeyHttpClient http;
  private final ApiKeyResolver resolver;

  public DefaultPasskeyClient(PasskeyHttpClient http, ApiKeyResolver resolver) {
    this.http = http;
    this.resolver = resolver;
  }

  @Override
  public RegistrationOptionsResponse beginRegistration(RegistrationBeginRequest req, Object ctx) {
    return http.post(
        REGISTER_OPTIONS, req, key(ctx), new TypeReference<RegistrationOptionsResponse>() {});
  }

  @Override
  public RegistrationResult finishRegistration(RegistrationVerifyRequest req, Object ctx) {
    return http.post(REGISTER_VERIFY, req, key(ctx), new TypeReference<RegistrationResult>() {});
  }

  @Override
  public AuthenticationOptionsResponse beginAuthentication(
      AuthenticationOptionsRequest req, Object ctx) {
    return http.post(
        AUTH_OPTIONS, req, key(ctx), new TypeReference<AuthenticationOptionsResponse>() {});
  }

  @Override
  public AuthenticationResult finishAuthentication(AuthenticationVerifyRequest req, Object ctx) {
    return http.post(AUTH_VERIFY, req, key(ctx), new TypeReference<AuthenticationResult>() {});
  }

  @Override
  public List<CredentialView> listCredentials(String externalUserId, Object ctx) {
    return http.get(
        CREDENTIALS,
        Map.of("externalUserId", externalUserId),
        key(ctx),
        new TypeReference<List<CredentialView>>() {});
  }

  @Override
  public CredentialView renameCredential(
      UUID id, String externalUserId, String nickname, Object ctx) {
    return http.patch(
        CREDENTIALS + "/" + id,
        new RpCredentialRenameRequest(externalUserId, nickname),
        key(ctx),
        new TypeReference<CredentialView>() {});
  }

  @Override
  public void deleteCredential(UUID id, String externalUserId, Object ctx) {
    http.delete(CREDENTIALS + "/" + id, Map.of("externalUserId", externalUserId), key(ctx));
  }

  @Override
  public RefreshResult refresh(String refreshToken, Object ctx) {
    return http.post(
        REFRESH, new RefreshRequest(refreshToken), key(ctx), new TypeReference<RefreshResult>() {});
  }

  private String key(Object requestCtx) {
    return resolver.resolve(requestCtx).apiKey();
  }
}
