package com.crosscert.passkey.fido2.cose;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

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
    try {
      Signature verifier = Signature.getInstance(jcaAlgorithm(key.algorithm()));
      verifier.initVerify(key.publicKey());
      verifier.update(signedData);
      return verifier.verify(signature);
    } catch (SignatureException e) {
      // Malformed signature (bad DER, wrong length) — a genuine verification failure.
      return false;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      // A provider misconfiguration or a key/algorithm mismatch — not a verification result.
      // Surface it rather than masking it as an invalid signature.
      throw new CoseException("signature verification could not run: " + e.getMessage(), e);
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
