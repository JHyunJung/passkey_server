package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import java.util.Map;

/**
 * The attestation object returned by {@code navigator.credentials.create()} (WebAuthn L3 §6.5): a
 * CBOR map of the attestation statement format, the format-specific attestation statement, and the
 * authenticator data.
 */
public record AttestationObject(
    String format, Map<?, ?> attestationStatement, AuthenticatorData authenticatorData) {

  /** Parse an attestation object from its raw CBOR encoding. */
  public static AttestationObject parse(byte[] cbor) {
    Object decoded = CborDecoder.decode(cbor);
    if (!(decoded instanceof Map<?, ?> map)) {
      throw new CborDecodeException("attestationObject is not a CBOR map");
    }
    Object fmt = map.get("fmt");
    Object attStmt = map.get("attStmt");
    Object authData = map.get("authData");
    if (!(fmt instanceof String fmtStr)) {
      throw new CborDecodeException("attestationObject.fmt missing or not a string");
    }
    if (!(attStmt instanceof Map<?, ?> attStmtMap)) {
      throw new CborDecodeException("attestationObject.attStmt missing or not a map");
    }
    if (!(authData instanceof byte[] authDataBytes)) {
      throw new CborDecodeException("attestationObject.authData missing or not a byte string");
    }
    return new AttestationObject(fmtStr, attStmtMap, AuthenticatorData.parse(authDataBytes));
  }
}
