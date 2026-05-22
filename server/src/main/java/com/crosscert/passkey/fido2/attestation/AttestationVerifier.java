package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.model.AttestationObject;

/**
 * Verifies one attestation statement format (WebAuthn L3 §8). Each implementation handles a single
 * {@code fmt} value. Milestone A shipped {@code none} and {@code packed}; Milestone B Phase 3 adds
 * {@code apple} and {@code android-key} (Task 6–7).
 *
 * <p>{@code trustAnchors} carries strict-mode policy: when non-null the verifier validates the
 * attestation certificate chain against MDS-sourced trust anchors and rejects revoked
 * authenticators; when null (non-strict) only the format's structural / signature checks run.
 * Sealed so the supported set is explicit.
 */
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier, PackedAttestationVerifier, AppleAnonymousAttestationVerifier {

  /** The {@code fmt} string this verifier handles. */
  String format();

  /**
   * Verify the attestation statement of {@code attestationObject} against {@code clientDataHash}
   * (SHA-256 of clientDataJSON). When {@code trustAnchors} is non-null, additionally validate the
   * attestation certificate chain to an MDS trust anchor and reject revoked authenticators. Throws
   * {@link Fido2VerificationException} on any failure.
   */
  AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException;
}
