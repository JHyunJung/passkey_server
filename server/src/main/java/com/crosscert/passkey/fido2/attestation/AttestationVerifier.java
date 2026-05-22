package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.model.AttestationObject;

/**
 * Verifies one attestation statement format (WebAuthn L3 §8). Each implementation handles a single
 * {@code fmt} value. Milestone A ships {@code none} and {@code packed} (self + full attestation;
 * non-strict — no trust-chain validation); Milestone B adds MDS trust-anchor validation for the
 * full-attestation variants. Sealed so the supported set is explicit.
 */
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier, PackedAttestationVerifier {

  /** The {@code fmt} string this verifier handles. */
  String format();

  /**
   * Verify the attestation statement of {@code attestationObject} against {@code clientDataHash}
   * (SHA-256 of clientDataJSON), or throw {@link Fido2VerificationException}.
   */
  AttestationResult verify(AttestationObject attestationObject, byte[] clientDataHash)
      throws Fido2VerificationException;
}
