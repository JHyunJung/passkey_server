package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * The {@code packed} attestation format (WebAuthn L3 §8.2). Handles both the self-attestation
 * variant (no {@code x5c}) and the full-attestation variant (with an {@code x5c} certificate
 * chain). For the full variant this verifier validates the attestation certificate's WebAuthn L3
 * §8.2.1 requirements (X.509 version 3, Basic Constraints CA=false, subject-OU "Authenticator
 * Attestation", and — when present — the FIDO AAGUID extension matching the authenticator data) and
 * verifies the attestation signature, but it does NOT validate the certificate chain's trust path
 * up to a root CA. Trust-anchor validation is the strict / MDS path's job (Milestone B) — this
 * matches the trust level webauthn4j's non-strict manager provides.
 */
public final class PackedAttestationVerifier implements AttestationVerifier {

  /** The FIDO AAGUID certificate extension OID (WebAuthn L3 §8.2.1). */
  private static final String FIDO_AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4";

  /** The exact subject-OU value WebAuthn L3 §8.2.1 mandates for a packed attestation cert. */
  private static final String REQUIRED_SUBJECT_OU = "Authenticator Attestation";

  @Override
  public String format() {
    return "packed";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
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
      return verifyFull(x5cObj, acd, algValue, signedData, signature, trustAnchors);
    } else {
      return verifySelf(acd, algValue, signedData, signature);
    }
  }

  /**
   * Full attestation (x5c present): validate the attestation certificate's WebAuthn L3 §8.2.1
   * requirements, verify the attestation signature with the certificate's public key, and — when
   * {@code trustAnchors} is non-null (strict mode) — validate the certificate chain to an MDS trust
   * anchor and reject revoked authenticators. When {@code trustAnchors} is null the chain trust
   * path is not validated (non-strict — matches webauthn4j's non-strict manager).
   */
  private static AttestationResult verifyFull(
      Object x5cObj,
      AttestedCredentialData acd,
      long algValue,
      byte[] signedData,
      byte[] signature,
      MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      // x5c is a CBOR array of DER-encoded X.509 certificates.
      if (!(x5cObj instanceof List<?> x5cList) || x5cList.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "packed x5c must be a non-empty array");
      }
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<X509Certificate> chain = new ArrayList<>();
      for (Object certObj : x5cList) {
        if (!(certObj instanceof byte[] certDer)) {
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID,
              "packed x5c element must be a DER-encoded certificate");
        }
        chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer)));
      }
      X509Certificate cert = chain.get(0);

      // WebAuthn L3 §8.2.1: validate the attestation certificate's integrity requirements.
      verifyAttestationCertificateRequirements(cert, acd);

      // Verify the signature using the attestation cert's public key.
      String jcaAlg = jcaAlgorithmForCoseAlg(algValue);
      java.security.Signature verifier = java.security.Signature.getInstance(jcaAlg);
      verifier.initVerify(cert.getPublicKey());
      verifier.update(signedData);
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "packed full attestation signature invalid against attestation cert");
      }

      // Strict mode (trustAnchors != null): validate the chain to an MDS trust anchor and reject
      // revoked authenticators. Non-strict (null): the chain trust path is not validated.
      if (trustAnchors != null) {
        verifyTrustAnchor(chain, acd, trustAnchors);
      }
      return new AttestationResult("packed", trustAnchors != null);
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
   * Strict-mode trust validation: reject a revoked authenticator, then validate the attestation
   * certificate chain to one of the MDS trust anchors registered for the credential's AAGUID.
   */
  private static void verifyTrustAnchor(
      List<X509Certificate> chain, AttestedCredentialData acd, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    UUID aaguid = aaguidOf(acd);
    Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
    if (entry.isEmpty()) {
      throw new Fido2VerificationException(
          FailureReason.MDS_TRUST_FAILED,
          "no MDS entry for AAGUID " + aaguid + " — authenticator not in metadata");
    }
    if (entry.get().isRevoked()) {
      throw new Fido2VerificationException(
          FailureReason.AUTHENTICATOR_REVOKED,
          "authenticator AAGUID " + aaguid + " is revoked or compromised per MDS");
    }
    if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
      throw new Fido2VerificationException(
          FailureReason.TRUST_PATH_INVALID,
          "attestation certificate chain does not validate to an MDS trust anchor");
    }
  }

  /** Decode the 16-byte AAGUID of {@code acd} into a {@link UUID}. */
  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }

  /**
   * Validates the WebAuthn L3 §8.2.1 attestation-certificate requirements: X.509 version 3, Basic
   * Constraints CA component {@code false}, subject organizational unit exactly {@code
   * "Authenticator Attestation"}, and — when the optional FIDO AAGUID extension is present — its
   * value matching the authenticator data's AAGUID. These are certificate-integrity checks; the
   * certificate chain's trust path is not validated here.
   */
  private static void verifyAttestationCertificateRequirements(
      X509Certificate cert, AttestedCredentialData acd) throws Fido2VerificationException {
    // §8.2.1: the attestation certificate MUST be X.509 version 3 (getVersion() returns 3).
    if (cert.getVersion() != 3) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed attestation cert is not X.509 version 3: v" + cert.getVersion());
    }

    // §8.2.1: the Basic Constraints extension MUST have the CA component set to false.
    // getBasicConstraints() returns -1 when the cert is not a CA; any other value means CA=true.
    if (cert.getBasicConstraints() != -1) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed attestation cert Basic Constraints CA must be false");
    }

    // §8.2.1: the subject OU MUST be exactly "Authenticator Attestation".
    String subjectOu = subjectOrganizationalUnit(cert);
    if (!REQUIRED_SUBJECT_OU.equals(subjectOu)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed attestation cert subject OU must be \""
              + REQUIRED_SUBJECT_OU
              + "\" but was \""
              + subjectOu
              + "\"");
    }

    // §8.2.1: if the FIDO AAGUID extension is present, its value MUST match the authData AAGUID.
    byte[] certAaguid = fidoAaguidExtension(cert);
    if (certAaguid != null && !Arrays.equals(certAaguid, acd.aaguid())) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed attestation cert AAGUID extension does not match authenticator data AAGUID");
    }
  }

  /**
   * Returns the value of the subject DN's {@code OU} (organizationalUnitName) attribute, or {@code
   * null} when the subject has no OU RDN.
   */
  private static String subjectOrganizationalUnit(X509Certificate cert)
      throws Fido2VerificationException {
    try {
      LdapName subject = new LdapName(cert.getSubjectX500Principal().getName());
      for (Rdn rdn : subject.getRdns()) {
        if ("OU".equalsIgnoreCase(rdn.getType())) {
          return String.valueOf(rdn.getValue());
        }
      }
      return null;
    } catch (InvalidNameException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed attestation cert subject DN is unparseable: " + e.getMessage());
    }
  }

  /**
   * Extracts the 16-byte AAGUID from the FIDO AAGUID certificate extension (OID {@code
   * 1.3.6.1.4.1.45724.1.1.4}), or {@code null} when the extension is absent (it is optional).
   *
   * <p>{@link X509Certificate#getExtensionValue} returns the extension value wrapped in an outer
   * DER {@code OCTET STRING}. The FIDO AAGUID extension's own content is itself a DER {@code OCTET
   * STRING} holding the raw 16 AAGUID bytes — so two {@code OCTET STRING} layers must be unwrapped.
   */
  private static byte[] fidoAaguidExtension(X509Certificate cert)
      throws Fido2VerificationException {
    byte[] raw = cert.getExtensionValue(FIDO_AAGUID_EXTENSION_OID);
    if (raw == null) {
      return null; // extension is optional
    }
    byte[] inner = DerUtil.unwrapOctetString(raw, "FIDO AAGUID extension outer OCTET STRING");
    byte[] aaguid = DerUtil.unwrapOctetString(inner, "FIDO AAGUID extension inner OCTET STRING");
    if (aaguid.length != 16) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed attestation cert AAGUID extension is not 16 bytes: " + aaguid.length);
    }
    return aaguid;
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
