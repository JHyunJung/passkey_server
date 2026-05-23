package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code android-key} attestation format (WebAuthn L3 §8.4). The attestation statement carries
 * {@code alg}, {@code sig}, and an {@code x5c} chain. Verification:
 *
 * <ol>
 *   <li>Verify {@code sig} over {@code authenticatorData || clientDataHash} with the public key of
 *       the credential certificate (x5c[0]).
 *   <li>Require that certificate's public key to equal the credential public key (by JCA {@code
 *       PublicKey.equals}, not by SubjectPublicKeyInfo bytes — robust to encoding variants).
 *   <li>Require the Android Key Attestation extension (OID {@code 1.3.6.1.4.1.11129.2.1.17})'s
 *       {@code attestationChallenge} (index 4 of the {@code KeyDescription} SEQUENCE) to equal
 *       {@code clientDataHash}.
 * </ol>
 *
 * <p>The certificate chain trust path is validated only in strict mode ({@code trustAnchors}
 * non-null).
 */
public final class AndroidKeyAttestationVerifier implements AttestationVerifier {

  /** The Android Key Attestation certificate extension OID. */
  private static final String ANDROID_KEY_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";

  @Override
  public String format() {
    return "android-key";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object sigObj = attStmt.get("sig");
      Object algObj = attStmt.get("alg");
      Object x5cObj = attStmt.get("x5c");
      if (!(sigObj instanceof byte[] signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation missing sig");
      }
      if (!(algObj instanceof Long algValue)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation missing alg");
      }
      if (!(x5cObj instanceof List<?> x5cList)
          || x5cList.isEmpty()
          || !(x5cList.get(0) instanceof byte[] certDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation missing x5c");
      }
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL,
            "android-key attestation has no attested credential");
      }

      // 1. Verify sig over authData || clientDataHash with the credential cert public key.
      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.writeBytes(attestationObject.authenticatorData().rawBytes());
      signedData.writeBytes(clientDataHash);
      Signature verifier = Signature.getInstance(jcaAlgorithmForCoseAlg(algValue));
      verifier.initVerify(cert.getPublicKey());
      verifier.update(signedData.toByteArray());
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation signature invalid");
      }

      // 2. The certificate public key must equal the credential public key. JCA PublicKey.equals
      // compares algorithm-specific key material — robust to SubjectPublicKeyInfo encoding
      // variants.
      if (!cert.getPublicKey().equals(acd.coseKey().publicKey())) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-key cert public key does not match credential public key");
      }

      // 3. The Android Key Attestation extension's attestationChallenge must equal clientDataHash.
      byte[] attestationChallenge = androidKeyAttestationChallenge(cert);
      if (!MessageDigest.isEqual(attestationChallenge, clientDataHash)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-key attestationChallenge does not match clientDataHash");
      }

      // strict mode: validate the cert chain to an Android trust anchor from MDS.
      if (trustAnchors != null) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Object o : x5cList) {
          if (!(o instanceof byte[] der)) {
            throw new Fido2VerificationException(
                FailureReason.ATTESTATION_INVALID,
                "android-key x5c element must be a DER-encoded certificate");
          }
          chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — android-key authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "android-key authenticator AAGUID " + aaguid + " is revoked or compromised per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "android-key chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("android-key", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "android-key attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Extract the {@code attestationChallenge} OCTET STRING from the Android Key Attestation
   * certificate extension. The extension content is a {@code KeyDescription} SEQUENCE whose fifth
   * element (index 4) is the {@code attestationChallenge} OCTET STRING.
   */
  private static byte[] androidKeyAttestationChallenge(X509Certificate cert)
      throws Fido2VerificationException {
    byte[] raw = cert.getExtensionValue(ANDROID_KEY_EXTENSION_OID);
    if (raw == null) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "android-key cert has no Key Attestation extension");
    }
    byte[] keyDescription =
        DerUtil.unwrapOctetString(raw, "android-key extension outer OCTET STRING");
    return DerUtil.extractAndroidKeyAttestationChallenge(keyDescription);
  }

  private static String jcaAlgorithmForCoseAlg(long coseAlg) throws Fido2VerificationException {
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default ->
          throw new Fido2VerificationException(
              FailureReason.UNSUPPORTED_ALGORITHM,
              "android-key attestation unsupported alg: " + coseAlg);
    };
  }

  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
