package com.crosscert.passkey.rp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RegistrationOptionsResponse(
    UUID ceremonyId,
    String challenge,
    Rp rp,
    User user,
    List<PubKeyCredParam> pubKeyCredParams,
    int timeout,
    String attestation,
    AuthenticatorSelection authenticatorSelection,
    @JsonInclude(JsonInclude.Include.NON_EMPTY) List<ExcludeCredential> excludeCredentials,
    @JsonInclude(JsonInclude.Include.NON_EMPTY) Map<String, Object> extensions) {

  public record Rp(String id, String name) {}

  public record User(String id, String name, String displayName) {}

  public record PubKeyCredParam(String type, long alg) {}

  public record AuthenticatorSelection(
      String userVerification, String residentKey, boolean requireResidentKey) {}

  public record ExcludeCredential(String type, String id, String transports) {}
}
