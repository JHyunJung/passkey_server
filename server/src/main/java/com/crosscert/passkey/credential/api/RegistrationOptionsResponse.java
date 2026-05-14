package com.crosscert.passkey.credential.api;

import java.util.List;
import java.util.UUID;

public record RegistrationOptionsResponse(
    UUID ceremonyId,
    String challenge,
    Rp rp,
    User user,
    List<PubKeyCredParam> pubKeyCredParams,
    int timeout,
    String attestation,
    AuthenticatorSelection authenticatorSelection) {

  public record Rp(String id, String name) {}

  public record User(String id, String name, String displayName) {}

  public record PubKeyCredParam(String type, long alg) {}

  public record AuthenticatorSelection(
      String userVerification, String residentKey, boolean requireResidentKey) {}
}
