package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * The {@code packed} attestation format (WebAuthn L3 §8.2), self-attestation variant only — the
 * statement carries {@code alg} and {@code sig} but no {@code x5c} certificate chain. The signature
 * is verified with the credential public key itself over {@code authData || clientDataHash}. The
 * full (x5c) variant requires certificate-path validation and ships in Milestone B; an {@code x5c}
 * present here is rejected as an unsupported format.
 */
public final class PackedSelfAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "packed";
  }

  @Override
  public AttestationResult verify(AttestationObject attestationObject, byte[] clientDataHash)
      throws Fido2VerificationException {
    Map<?, ?> attStmt = attestationObject.attestationStatement();
    if (attStmt.containsKey("x5c")) {
      throw new Fido2VerificationException(
          FailureReason.UNSUPPORTED_ATTESTATION_FORMAT,
          "packed full attestation (x5c) is not supported in Milestone A");
    }
    Object sig = attStmt.get("sig");
    if (!(sig instanceof byte[] signature)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed attestation missing sig");
    }
    AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
    if (acd == null) {
      throw new Fido2VerificationException(
          FailureReason.NO_ATTESTED_CREDENTIAL, "attestation has no attested credential data");
    }
    boolean signatureValid;
    try {
      CoseKey credentialKey = acd.coseKey();
      // WebAuthn L3 §8.2: the attestation statement's alg must equal the credential public
      // key's algorithm — a self-attestation signs with the credential key itself.
      Object alg = attStmt.get("alg");
      if (!(alg instanceof Long algValue) || algValue != credentialKey.algorithm()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "packed self-attestation alg does not match credential public key alg");
      }
      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.writeBytes(attestationObject.authenticatorData().rawBytes());
      signedData.writeBytes(clientDataHash);
      signatureValid =
          CoseSignatureVerifier.verify(credentialKey, signedData.toByteArray(), signature);
    } catch (CborDecodeException | CoseException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed self-attestation key/verify failed: " + e.getMessage());
    }
    if (!signatureValid) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed self-attestation signature invalid");
    }
    return new AttestationResult("packed", false);
  }
}
