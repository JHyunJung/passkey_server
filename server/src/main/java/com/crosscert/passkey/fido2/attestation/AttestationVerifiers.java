package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import java.util.Map;

/**
 * Dispatches an attestation {@code fmt} string to its {@link AttestationVerifier}. Registers {@code
 * none}, {@code packed}, {@code apple}, and {@code android-key}; any other format throws {@code
 * UNSUPPORTED_ATTESTATION_FORMAT} (fail-closed).
 */
public final class AttestationVerifiers {

  private static final Map<String, AttestationVerifier> REGISTRY =
      Map.of(
          "none", new NoneAttestationVerifier(),
          "packed", new PackedAttestationVerifier(),
          "apple", new AppleAnonymousAttestationVerifier(),
          "android-key", new AndroidKeyAttestationVerifier());

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
