package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import com.crosscert.passkey.fido2.cose.CoseKey;
import java.util.Arrays;

/**
 * The attested credential data embedded in authenticator data when the AT flag is set (WebAuthn L3
 * §6.5.1): the authenticator AAGUID, the new credential id, and the credential public key as a
 * COSE_Key.
 *
 * <p>The byte layout — {@code aaguid(16) || credentialIdLength(2, big-endian) || credentialId ||
 * coseKey} — is identical to the form webauthn4j's {@code AttestedCredentialDataConverter} writes
 * into our {@code credential.public_key_cose} column, so {@link #parse(byte[])} reads existing
 * stored credentials without any migration.
 *
 * <p>The COSE key is held as raw bytes and only parsed (and curve-validated) when {@link
 * #coseKey()} is called, so constructing this record never fails on an unusual key.
 */
public record AttestedCredentialData(byte[] aaguid, byte[] credentialId, byte[] coseKeyBytes) {

  /** The credential public key parsed from {@link #coseKeyBytes()}. */
  public CoseKey coseKey() {
    return CoseKey.parse(coseKeyBytes);
  }

  /**
   * Parse attested credential data from a byte array whose entire remaining content after the fixed
   * header is a single COSE_Key. Used for the standalone {@code credential.public_key_cose} column.
   */
  public static AttestedCredentialData parse(byte[] data) {
    Parsed p = parseWithLength(data, 0);
    return p.value();
  }

  /**
   * Parse attested credential data starting at {@code offset} within a larger buffer (the
   * authenticator data case, where extension data may follow). Reports the end offset so the caller
   * can continue parsing.
   */
  public static Parsed parseWithLength(byte[] data, int offset) {
    if (data.length < offset + 18) {
      throw new CborDecodeException("attested credential data truncated");
    }
    byte[] aaguid = Arrays.copyOfRange(data, offset, offset + 16);
    int credIdLen = ((data[offset + 16] & 0xff) << 8) | (data[offset + 17] & 0xff);
    int credIdEnd = offset + 18 + credIdLen;
    if (data.length < credIdEnd) {
      throw new CborDecodeException("attested credential data credentialId truncated");
    }
    byte[] credentialId = Arrays.copyOfRange(data, offset + 18, credIdEnd);
    // The COSE_Key is the next CBOR item; decodeWithLength tells us where it ends.
    byte[] rest = Arrays.copyOfRange(data, credIdEnd, data.length);
    CborDecoder.DecodeResult cose = CborDecoder.decodeWithLength(rest);
    byte[] coseBytes = Arrays.copyOfRange(rest, 0, cose.consumed());
    return new Parsed(
        new AttestedCredentialData(aaguid, credentialId, coseBytes), credIdEnd + cose.consumed());
  }

  /** An {@link AttestedCredentialData} paired with the offset where parsing finished. */
  public record Parsed(AttestedCredentialData value, int endOffset) {}
}
