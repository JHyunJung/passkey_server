package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The client data collected by the browser for a ceremony (WebAuthn L3 §5.8.1), parsed from
 * clientDataJSON. The verifier checks {@link #type()}, {@link #challenge()} and {@link #origin()}
 * against the values the server expects.
 */
public record CollectedClientData(
    String type, String challenge, String origin, boolean crossOrigin) {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** Parse clientDataJSON (UTF-8 encoded JSON). */
  public static CollectedClientData parse(byte[] clientDataJson) {
    try {
      JsonNode node = MAPPER.readTree(clientDataJson);
      JsonNode type = node.get("type");
      JsonNode challenge = node.get("challenge");
      JsonNode origin = node.get("origin");
      if (type == null || challenge == null || origin == null) {
        throw new CborDecodeException("clientDataJSON missing a required field");
      }
      JsonNode crossOrigin = node.get("crossOrigin");
      return new CollectedClientData(
          type.asText(),
          challenge.asText(),
          origin.asText(),
          crossOrigin != null && crossOrigin.asBoolean(false));
    } catch (CborDecodeException e) {
      throw e;
    } catch (Exception e) {
      throw new CborDecodeException("clientDataJSON is not valid JSON");
    }
  }
}
