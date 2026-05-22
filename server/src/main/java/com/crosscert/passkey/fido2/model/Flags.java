package com.crosscert.passkey.fido2.model;

/**
 * The authenticator data flags byte (WebAuthn L3 §6.1). Each bit is a boolean signal the verifier
 * checks: UP and UV gate user presence/verification, AT signals an embedded attested credential, ED
 * signals extension data, and BE/BS carry CTAP 2.1 backup eligibility / state.
 */
public record Flags(
    boolean userPresent,
    boolean userVerified,
    boolean backupEligible,
    boolean backupState,
    boolean attestedCredentialDataIncluded,
    boolean extensionDataIncluded) {

  /** Decode the single flags byte from authenticator data. */
  public static Flags from(byte b) {
    int v = b & 0xff;
    return new Flags(
        (v & 0x01) != 0, // UP — bit 0
        (v & 0x04) != 0, // UV — bit 2
        (v & 0x08) != 0, // BE — bit 3
        (v & 0x10) != 0, // BS — bit 4
        (v & 0x40) != 0, // AT — bit 6
        (v & 0x80) != 0); // ED — bit 7
  }
}
