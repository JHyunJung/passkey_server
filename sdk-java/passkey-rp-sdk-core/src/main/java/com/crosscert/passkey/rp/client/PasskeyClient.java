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
import java.util.List;
import java.util.UUID;

/**
 * High-level facade. Eight methods, one per RP-facing server endpoint. Implementations attach the
 * tenant's API key, propagate {@code traceId} via MDC, unwrap the {@code ApiResponse} envelope, and
 * surface failures as typed exceptions from {@link com.crosscert.passkey.rp.error}.
 */
public interface PasskeyClient {

  RegistrationOptionsResponse beginRegistration(RegistrationBeginRequest req, Object requestCtx);

  RegistrationResult finishRegistration(RegistrationVerifyRequest req, Object requestCtx);

  AuthenticationOptionsResponse beginAuthentication(
      AuthenticationOptionsRequest req, Object requestCtx);

  AuthenticationResult finishAuthentication(AuthenticationVerifyRequest req, Object requestCtx);

  List<CredentialView> listCredentials(String externalUserId, Object requestCtx);

  CredentialView renameCredential(
      UUID id, String externalUserId, String nickname, Object requestCtx);

  void deleteCredential(UUID id, String externalUserId, Object requestCtx);

  RefreshResult refresh(String refreshToken, Object requestCtx);
}
