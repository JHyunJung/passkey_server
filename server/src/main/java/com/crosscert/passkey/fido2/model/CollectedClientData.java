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

  private static final ObjectMapper MAPPER = buildMapper();

  private static ObjectMapper buildMapper() {
    // clientDataJSON is a flat 4-field object; cap nesting depth so a hostile deeply-nested
    // payload cannot exhaust the parser — the same fail-closed stance the CBOR decoder takes.
    com.fasterxml.jackson.core.JsonFactory factory =
        com.fasterxml.jackson.core.JsonFactory.builder()
            .streamReadConstraints(
                com.fasterxml.jackson.core.StreamReadConstraints.builder()
                    .maxNestingDepth(20)
                    .build())
            .build();
    return new ObjectMapper(factory);
  }

  /** Parse clientDataJSON (UTF-8 encoded JSON). */
  public static CollectedClientData parse(byte[] clientDataJson) {
    try {
      if (clientDataJson.length > 8192) {
        throw new CborDecodeException("clientDataJSON exceeds 8 KiB limit");
      }
      JsonNode node = MAPPER.readTree(clientDataJson);
      JsonNode type = node.get("type");
      JsonNode challenge = node.get("challenge");
      JsonNode origin = node.get("origin");
      if (type == null || challenge == null || origin == null) {
        throw new CborDecodeException("clientDataJSON missing a required field");
      }
      if (!type.isTextual() || !challenge.isTextual() || !origin.isTextual()) {
        throw new CborDecodeException("clientDataJSON type/challenge/origin must be strings");
      }
      JsonNode crossOrigin = node.get("crossOrigin");
      if (crossOrigin != null && !crossOrigin.isBoolean()) {
        throw new CborDecodeException("clientDataJSON crossOrigin must be a boolean");
      }
      return new CollectedClientData(
          type.asText(),
          challenge.asText(),
          origin.asText(),
          crossOrigin != null && crossOrigin.booleanValue());
    } catch (CborDecodeException e) {
      throw e;
    } catch (Exception e) {
      throw new CborDecodeException("clientDataJSON is not valid JSON", e);
    }
  }
}
