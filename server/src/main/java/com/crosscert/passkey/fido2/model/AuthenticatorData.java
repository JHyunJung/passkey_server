package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import java.util.Arrays;

/**
 * Parsed WebAuthn authenticator data (WebAuthn L3 §6.1): the SHA-256 of the RP id, the {@link
 * Flags} byte, a 32-bit signature counter, and — when the AT flag is set — the embedded {@link
 * AttestedCredentialData}. Extension data, when present, is not interpreted in Milestone A.
 */
public record AuthenticatorData(
    byte[] rpIdHash,
    Flags flags,
    long signCount,
    AttestedCredentialData attestedCredentialData,
    byte[] rawBytes) {

  private static final int HEADER_LENGTH = 37; // rpIdHash(32) + flags(1) + signCount(4)

  /** Parse authenticator data from its raw byte form. */
  public static AuthenticatorData parse(byte[] data) {
    if (data.length < HEADER_LENGTH) {
      throw new CborDecodeException("authenticator data shorter than 37-byte header");
    }
    byte[] rpIdHash = Arrays.copyOfRange(data, 0, 32);
    Flags flags = Flags.from(data[32]);
    long signCount =
        ((data[33] & 0xffL) << 24)
            | ((data[34] & 0xffL) << 16)
            | ((data[35] & 0xffL) << 8)
            | (data[36] & 0xffL);
    AttestedCredentialData acd = null;
    if (flags.attestedCredentialDataIncluded()) {
      acd = AttestedCredentialData.parseWithLength(data, HEADER_LENGTH).value();
    }
    return new AuthenticatorData(rpIdHash, flags, signCount, acd, data);
  }
}
