package com.crosscert.passkey.credential.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record RegistrationOptionsResponse(
    UUID ceremonyId,
    String challenge,
    Rp rp,
    User user,
    List<PubKeyCredParam> pubKeyCredParams,
    int timeout,
    String attestation,
    AuthenticatorSelection authenticatorSelection,
    /**
     * Active credentials already registered to this user. Authenticator-side hint to refuse a
     * second enrolment from the same device — closes the duplicate-register UX gap described in
     * WebAuthn L3 §5.1.3. Omitted entirely when the user has no active credentials so newly
     * onboarded users see a clean payload.
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY) List<ExcludeCredential> excludeCredentials,
    /**
     * WebAuthn extension inputs (omitted when no tenant policy requires any). Today only the CTAP2
     * {@code credentialProtectionPolicy} entry is populated.
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY) Map<String, Object> extensions) {

  public record Rp(String id, String name) {}

  public record User(String id, String name, String displayName) {}

  public record PubKeyCredParam(String type, long alg) {}

  public record AuthenticatorSelection(
      String userVerification, String residentKey, boolean requireResidentKey) {}

  public record ExcludeCredential(String type, String id, String transports) {}
}
