package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import java.util.Map;

/**
 * Dispatches an attestation {@code fmt} string to its {@link AttestationVerifier}. Registers {@code
 * none}, {@code packed}, {@code apple}, {@code android-key}, {@code android-safetynet}, {@code
 * fido-u2f}, and {@code tpm}; any other format throws {@code UNSUPPORTED_ATTESTATION_FORMAT}
 * (fail-closed).
 */
public final class AttestationVerifiers {

  private static final Map<String, AttestationVerifier> REGISTRY =
      Map.ofEntries(
          Map.entry("none", new NoneAttestationVerifier()),
          Map.entry("packed", new PackedAttestationVerifier()),
          Map.entry("apple", new AppleAnonymousAttestationVerifier()),
          Map.entry("android-key", new AndroidKeyAttestationVerifier()),
          Map.entry("android-safetynet", new AndroidSafetyNetAttestationVerifier()),
          Map.entry("fido-u2f", new FidoU2fAttestationVerifier()),
          Map.entry("tpm", new TpmAttestationVerifier()));

  private AttestationVerifiers() {}

  /** Return the verifier for {@code fmt}, or throw if the format is not supported. */
  public static AttestationVerifier forFormat(String fmt) throws Fido2VerificationException {
    AttestationVerifier verifier = REGISTRY.get(fmt);
    if (verifier == null) {
      throw new Fido2VerificationException(
          FailureReason.UNSUPPORTED_ATTESTATION_FORMAT, "unsupported attestation format: " + fmt);
    }
    return verifier;
  }
}
