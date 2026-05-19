package com.crosscert.passkey.rp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthenticationOptionsResponse(
    UUID ceremonyId,
    String challenge,
    int timeout,
    String rpId,
    List<AllowCredential> allowCredentials,
    String userVerification) {

  public record AllowCredential(String type, String id, String transports) {}
}
