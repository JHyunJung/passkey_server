package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * The {@code packed} attestation format (WebAuthn L3 §8.2). Handles both the self-attestation
 * variant (no {@code x5c}) and the full-attestation variant (with an {@code x5c} certificate
 * chain). This verifier checks only that the attestation signature is valid — it does NOT validate
 * the certificate chain's trust path up to a root CA. Trust-anchor validation is the job of the
 * strict / MDS path (Milestone B); a non-strict tenant accepts packed full attestation at the same
 * trust level webauthn4j's non-strict manager did.
 */
public final class PackedAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "packed";
  }

  @Override
  public AttestationResult verify(AttestationObject attestationObject, byte[] clientDataHash)
      throws Fido2VerificationException {
    Map<?, ?> attStmt = attestationObject.attestationStatement();

    // 1. Extract sig and alg — missing or wrong type is ATTESTATION_INVALID.
    Object sigObj = attStmt.get("sig");
    if (!(sigObj instanceof byte[] signature)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed attestation missing sig");
    }
    Object algObj = attStmt.get("alg");
    if (!(algObj instanceof Long algValue)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed attestation missing alg");
    }

    // 2. attestedCredentialData must be present.
    AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
    if (acd == null) {
      throw new Fido2VerificationException(
          FailureReason.NO_ATTESTED_CREDENTIAL, "attestation has no attested credential data");
    }

    // 3. signedData = authData.rawBytes() || clientDataHash.
    ByteArrayOutputStream signedDataOut = new ByteArrayOutputStream();
    signedDataOut.writeBytes(attestationObject.authenticatorData().rawBytes());
    signedDataOut.writeBytes(clientDataHash);
    byte[] signedData = signedDataOut.toByteArray();

    // 4. Branch on x5c presence.
    Object x5cObj = attStmt.get("x5c");
    if (x5cObj != null) {
      return verifyFull(x5cObj, algValue, signedData, signature);
    } else {
      return verifySelf(acd, algValue, signedData, signature);
    }
  }

  /**
   * Full attestation (x5c present): verify the signature with the attestation certificate's public
   * key. The certificate chain trust path is NOT validated here — that is Milestone B / MDS strict
   * mode. This matches the behavior of webauthn4j's non-strict manager.
   */
  private static AttestationResult verifyFull(
      Object x5cObj, long algValue, byte[] signedData, byte[] signature)
      throws Fido2VerificationException {
    try {
      // x5c is a CBOR array of DER-encoded X.509 certificates.
      if (!(x5cObj instanceof List<?> x5cList) || x5cList.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "packed x5c must be a non-empty array");
      }
      Object firstCertObj = x5cList.get(0);
      if (!(firstCertObj instanceof byte[] certDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "packed x5c first element must be a DER-encoded certificate");
      }

      // Parse the attestation certificate.
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

      // Verify the signature using the attestation cert's public key.
      String jcaAlg = jcaAlgorithmForCoseAlg(algValue);
      java.security.Signature verifier = java.security.Signature.getInstance(jcaAlg);
      verifier.initVerify(cert.getPublicKey());
      verifier.update(signedData);
      boolean valid = verifier.verify(signature);
      if (!valid) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "packed full attestation signature invalid against attestation cert");
      }
      return new AttestationResult("packed", true);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (CertificateException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed x5c certificate parse failed: " + e.getMessage());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed full attestation algorithm/key error: " + e.getMessage());
    } catch (SignatureException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed full attestation malformed signature: " + e.getMessage());
    } catch (RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed full attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Self attestation (no x5c): verify the signature with the credential public key. The attStmt alg
   * must equal the credential key's algorithm per WebAuthn L3 §8.2.
   */
  private static AttestationResult verifySelf(
      AttestedCredentialData acd, long algValue, byte[] signedData, byte[] signature)
      throws Fido2VerificationException {
    try {
      CoseKey credentialKey = acd.coseKey();
      // WebAuthn L3 §8.2: the attestation statement's alg must equal the credential public
      // key's algorithm — a self-attestation signs with the credential key itself.
      if (algValue != credentialKey.algorithm()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "packed self-attestation alg does not match credential public key alg");
      }
      boolean signatureValid = CoseSignatureVerifier.verify(credentialKey, signedData, signature);
      if (!signatureValid) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "packed self-attestation signature invalid");
      }
      return new AttestationResult("packed", false);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (CborDecodeException | CoseException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed self-attestation key/verify failed: " + e.getMessage());
    }
  }

  /**
   * Maps a COSE algorithm identifier to a JCA algorithm name for signature verification. Only ES256
   * and RS256 are supported for packed attestation in Milestone A.
   */
  private static String jcaAlgorithmForCoseAlg(long coseAlg) throws Fido2VerificationException {
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default ->
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID, "packed attestation unsupported alg: " + coseAlg);
    };
  }
}
