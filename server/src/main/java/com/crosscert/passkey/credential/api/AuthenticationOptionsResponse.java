package com.crosscert.passkey.credential.api;

import java.util.List;
import java.util.UUID;

public record AuthenticationOptionsResponse(
    UUID ceremonyId,
    String challenge,
    int timeout,
    String rpId,
    List<AllowCredential> allowCredentials,
    String userVerification) {

  public record AllowCredential(String type, String id, String transports) {}
}
