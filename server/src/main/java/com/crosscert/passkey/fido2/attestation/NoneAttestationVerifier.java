package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.model.AttestationObject;

/**
 * The {@code none} attestation format (WebAuthn L3 §8.7): the authenticator provides no
 * attestation. The only check is that the attestation statement is empty — a non-empty statement
 * under {@code fmt=none} is malformed input and is rejected.
 *
 * <p>Strict mode: rejected. The {@code none} format carries no attestation certificate, so it
 * cannot chain to an MDS trust anchor. Strict-tenant registrations of {@code fmt=none} are rejected
 * with {@link FailureReason#ATTESTATION_INVALID}.
 */
public final class NoneAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "none";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    if (trustAnchors != null) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "fmt=none cannot satisfy strict MDS requirement — no attestation certificate to chain to a trust anchor");
    }
    // none attestation carries no certificate — trustAnchors is not applicable.
    if (!attestationObject.attestationStatement().isEmpty()) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "none attestation must have an empty statement");
    }
    return new AttestationResult("none", false);
  }
}
