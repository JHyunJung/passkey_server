package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code android-safetynet} attestation format (WebAuthn L3 §8.5). The attestation statement
 * carries {@code ver} and {@code response} — a SafetyNet attestation JWS. Verification:
 *
 * <ol>
 *   <li>Parse {@code response} as a JWS. The leaf certificate in the {@code x5c} JWS header is the
 *       AndroidAttest cert; verify the JWS RSA signature with its public key.
 *   <li>Verify the leaf certificate's subject alternative name is {@code attest.android.com}.
 *   <li>Decode the JWS payload as JSON; require {@code nonce == base64(SHA-256(authenticatorData ||
 *       clientDataHash))}, {@code ctsProfileMatch == true}, {@code basicIntegrity == true}.
 *   <li>Strict mode: validate the JWS x5c chain to an MDS trust anchor for the credential's AAGUID
 *       (often the zero AAGUID for SafetyNet — verifier accepts whatever the MDS entry holds).
 * </ol>
 */
public final class AndroidSafetyNetAttestationVerifier implements AttestationVerifier {

  public static final String EXPECTED_LEAF_SAN = "attest.android.com";

  private static final int SAN_TYPE_DNS_NAME = 2; // RFC 5280 §4.2.1.6

  @Override
  public String format() {
    return "android-safetynet";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object verObj = attStmt.get("ver");
      if (!(verObj instanceof String verStr) || verStr.isBlank()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet attestation missing or empty ver");
      }
      Object responseObj = attStmt.get("response");
      if (!(responseObj instanceof byte[] responseBytes)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet attestation missing response");
      }
      String jwsCompact = new String(responseBytes, StandardCharsets.UTF_8);
      JWSObject jws;
      try {
        jws = JWSObject.parse(jwsCompact);
      } catch (java.text.ParseException e) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet response is not a parseable JWS: " + e.getMessage());
      }

      List<X509Certificate> chain = parseX5c(jws);
      if (chain.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet JWS has no x5c chain");
      }
      X509Certificate leaf = chain.get(0);
      if (!leafSanMatches(leaf, EXPECTED_LEAF_SAN)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet leaf cert SAN must be " + EXPECTED_LEAF_SAN);
      }
      if (!jws.verify(
          new RSASSAVerifier((java.security.interfaces.RSAPublicKey) leaf.getPublicKey()))) {
        throw new Fido2VerificationException(
            FailureReason.SIGNATURE_INVALID, "android-safetynet JWS signature invalid");
      }

      JWTClaimsSet claims;
      try {
        claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());
      } catch (java.text.ParseException e) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet JWS payload is not a JSON object: " + e.getMessage());
      }
      String nonce = claims.getStringClaim("nonce");
      if (nonce == null) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet payload missing nonce");
      }
      ByteArrayOutputStream nonceInput = new ByteArrayOutputStream();
      nonceInput.writeBytes(attestationObject.authenticatorData().rawBytes());
      nonceInput.writeBytes(clientDataHash);
      byte[] expectedNonce = MessageDigest.getInstance("SHA-256").digest(nonceInput.toByteArray());
      byte[] actualNonce = java.util.Base64.getDecoder().decode(nonce);
      if (!MessageDigest.isEqual(expectedNonce, actualNonce)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet nonce does not match SHA-256(authData || clientDataHash)");
      }
      Boolean ctsProfileMatch = claims.getBooleanClaim("ctsProfileMatch");
      if (!Boolean.TRUE.equals(ctsProfileMatch)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet ctsProfileMatch is not true");
      }
      Boolean basicIntegrity = claims.getBooleanClaim("basicIntegrity");
      if (!Boolean.TRUE.equals(basicIntegrity)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet basicIntegrity is not true");
      }

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL,
            "android-safetynet attestation has no attested credential");
      }
      if (trustAnchors != null) {
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — safetynet authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "android-safetynet authenticator AAGUID " + aaguid + " is revoked per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "android-safetynet chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("android-safetynet", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (Exception e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "android-safetynet attestation verification failed: " + e.getMessage());
    }
  }

  private static List<X509Certificate> parseX5c(JWSObject jws) throws Exception {
    Collection<com.nimbusds.jose.util.Base64> x5c = jws.getHeader().getX509CertChain();
    if (x5c == null) {
      return List.of();
    }
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<X509Certificate> chain = new ArrayList<>();
    for (com.nimbusds.jose.util.Base64 b64 : x5c) {
      chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(b64.decode())));
    }
    return chain;
  }

  private static boolean leafSanMatches(X509Certificate leaf, String expected) throws Exception {
    Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
    if (sans == null) {
      return false;
    }
    for (List<?> entry : sans) {
      // Each SAN entry is [type, value]. Type SAN_TYPE_DNS_NAME = dNSName.
      if (entry.size() >= 2
          && Objects.equals(entry.get(0), SAN_TYPE_DNS_NAME)
          && expected.equalsIgnoreCase(String.valueOf(entry.get(1)))) {
        return true;
      }
    }
    return false;
  }

  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
