package com.crosscert.passkey.fido2.cose;

import java.security.GeneralSecurityException;
import java.security.Signature;

/**
 * Verifies a signature produced by an authenticator's credential private key against the COSE
 * public key recorded at registration. ES256 signatures arrive as ASN.1 DER-encoded ECDSA values;
 * the JCA {@code SHA256withECDSA} signer consumes that form directly, so no manual DER unwrapping
 * is required.
 */
public final class CoseSignatureVerifier {

  private CoseSignatureVerifier() {}

  /** Returns {@code true} when {@code signature} is a valid signature of {@code signedData}. */
  public static boolean verify(CoseKey key, byte[] signedData, byte[] signature) {
    String jcaAlgorithm = jcaAlgorithm(key.algorithm());
    try {
      Signature verifier = Signature.getInstance(jcaAlgorithm);
      verifier.initVerify(key.publicKey());
      verifier.update(signedData);
      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      // A malformed signature (bad DER, wrong length) surfaces here — treat as a failed
      // verification rather than an error, the caller maps it to SIGNATURE_INVALID.
      return false;
    }
  }

  private static String jcaAlgorithm(long coseAlg) {
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default -> throw new CoseException("unsupported COSE algorithm: " + coseAlg);
    };
  }
}
