package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The {@code apple} anonymous attestation format (WebAuthn L3 §8.8). The attestation statement
 * carries only an {@code x5c} certificate chain — no signature field. Verification (per the Apple
 * Anonymous Attestation procedure):
 *
 * <ol>
 *   <li>Concatenate {@code authenticatorData || clientDataHash} and compute its SHA-256 — the
 *       expected nonce.
 *   <li>Read the nonce from the credential certificate's Apple extension (OID {@code
 *       1.2.840.113635.100.8.2}) and require it to equal the expected nonce.
 *   <li>Require the certificate's public key to equal the credential public key in the
 *       authenticator data.
 * </ol>
 *
 * <p>The certificate chain's trust path (to Apple's root) is validated only in strict mode, when
 * {@code trustAnchors} is non-null.
 */
public final class AppleAnonymousAttestationVerifier implements AttestationVerifier {

  /** Apple's anonymous attestation nonce certificate extension OID. */
  private static final String APPLE_NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";

  @Override
  public String format() {
    return "apple";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object x5cObj = attStmt.get("x5c");
      if (!(x5cObj instanceof List<?> x5cList) || x5cList.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "apple attestation missing x5c");
      }
      Object firstCertObj = x5cList.get(0);
      if (!(firstCertObj instanceof byte[] certDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "apple x5c first element must be a DER-encoded certificate");
      }
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL, "apple attestation has no attested credential");
      }

      // 1. expected nonce = SHA-256(authData || clientDataHash).
      ByteArrayOutputStream nonceInput = new ByteArrayOutputStream();
      nonceInput.writeBytes(attestationObject.authenticatorData().rawBytes());
      nonceInput.writeBytes(clientDataHash);
      byte[] expectedNonce = MessageDigest.getInstance("SHA-256").digest(nonceInput.toByteArray());

      // 2. nonce from the Apple certificate extension must equal the expected nonce.
      byte[] certNonce = appleNonceFromExtension(cert);
      if (!Arrays.equals(certNonce, expectedNonce)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "apple attestation nonce does not match authenticatorData||clientDataHash");
      }

      // 3. the certificate public key must equal the credential public key.
      byte[] certPublicKey = cert.getPublicKey().getEncoded();
      byte[] credentialPublicKey = acd.coseKey().publicKey().getEncoded();
      if (!Arrays.equals(certPublicKey, credentialPublicKey)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "apple attestation cert public key does not match credential public key");
      }

      // strict mode: validate the cert chain to an Apple trust anchor from MDS.
      if (trustAnchors != null) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Object o : x5cList) {
          if (!(o instanceof byte[] der)) {
            throw new Fido2VerificationException(
                FailureReason.ATTESTATION_INVALID,
                "apple x5c element must be a DER-encoded certificate");
          }
          chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        UUID aaguid = aaguidOf(acd);
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "apple attestation chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("apple", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "apple attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Extract the nonce octets from the Apple anonymous attestation certificate extension. The
   * extension value is a DER {@code SEQUENCE} whose single element is a context-tagged {@code [1]
   * EXPLICIT} wrapping an {@code OCTET STRING} of the SHA-256 nonce. {@link
   * java.security.cert.X509Certificate#getExtensionValue} wraps the extension content in an outer
   * {@code OCTET STRING}, so one extra unwrap is required first.
   */
  private static byte[] appleNonceFromExtension(X509Certificate cert)
      throws Fido2VerificationException {
    byte[] raw = cert.getExtensionValue(APPLE_NONCE_EXTENSION_OID);
    if (raw == null) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "apple attestation cert has no nonce extension");
    }
    byte[] inner = DerUtil.unwrapOctetString(raw, "Apple nonce extension outer OCTET STRING");
    return DerUtil.extractAppleNonce(inner);
  }

  /** Decode the 16-byte AAGUID of {@code acd} into a {@link UUID}. */
  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
