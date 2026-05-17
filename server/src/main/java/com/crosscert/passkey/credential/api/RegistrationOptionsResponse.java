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
     * WebAuthn extension inputs (omitted when no tenant policy requires any). Today only the CTAP2
     * {@code credentialProtectionPolicy} entry is populated.
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY) Map<String, Object> extensions) {

  public record Rp(String id, String name) {}

  public record User(String id, String name, String displayName) {}

  public record PubKeyCredParam(String type, long alg) {}

  public record AuthenticatorSelection(
      String userVerification, String residentKey, boolean requireResidentKey) {}
}
