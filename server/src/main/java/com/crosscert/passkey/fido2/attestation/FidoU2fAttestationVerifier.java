package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code fido-u2f} attestation format (WebAuthn L3 §8.6). Legacy U2F authenticators. The
 * attestation statement carries {@code sig} and {@code x5c}. Verification:
 *
 * <ol>
 *   <li>Require the credential public key to be EC P-256 — the U2F format predates COSE alg
 *       negotiation and only ES256 is defined.
 *   <li>Construct signed data {@code 0x00 || rpIdHash || clientDataHash || credentialId ||
 *       publicKeyU2F} where {@code publicKeyU2F = 0x04 || x || y} (uncompressed EC point).
 *   <li>Verify {@code sig} (SHA256withECDSA) over signed data with x5c[0]'s public key.
 *   <li>Strict mode: validate the chain to an MDS trust anchor for the credential's AAGUID
 *       (typically the zero AAGUID for U2F — the verifier accepts whatever MDS holds).
 * </ol>
 */
public final class FidoU2fAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "fido-u2f";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object sigObj = attStmt.get("sig");
      Object x5cObj = attStmt.get("x5c");
      if (!(sigObj instanceof byte[] signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "fido-u2f attestation missing sig");
      }
      if (!(x5cObj instanceof List<?> x5cList)
          || x5cList.isEmpty()
          || !(x5cList.get(0) instanceof byte[] leafDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "fido-u2f attestation missing x5c");
      }
      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL,
            "fido-u2f attestation has no attested credential");
      }

      CoseKey coseKey = acd.coseKey();
      if (!(coseKey.publicKey() instanceof ECPublicKey ecPub)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "fido-u2f credential key must be EC P-256 (alg ES256); got "
                + coseKey.publicKey().getAlgorithm());
      }
      byte[] publicKeyU2F = encodeU2fPublicKey(ecPub);

      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.write(0x00);
      signedData.writeBytes(attestationObject.authenticatorData().rpIdHash());
      signedData.writeBytes(clientDataHash);
      signedData.writeBytes(acd.credentialId());
      signedData.writeBytes(publicKeyU2F);

      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate leaf =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(leafDer));
      Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(leaf.getPublicKey());
      verifier.update(signedData.toByteArray());
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.SIGNATURE_INVALID, "fido-u2f attestation signature invalid");
      }

      if (trustAnchors != null) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Object o : x5cList) {
          if (!(o instanceof byte[] der)) {
            throw new Fido2VerificationException(
                FailureReason.ATTESTATION_INVALID,
                "fido-u2f x5c element must be DER-encoded certificate");
          }
          chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — U2F authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "fido-u2f authenticator AAGUID " + aaguid + " is revoked per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "fido-u2f chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("fido-u2f", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "fido-u2f attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Encode EC P-256 public key as the 65-byte uncompressed form: {@code 0x04 || x(32) || y(32)}.
   */
  private static byte[] encodeU2fPublicKey(ECPublicKey pub) {
    byte[] x = unsigned32(pub.getW().getAffineX());
    byte[] y = unsigned32(pub.getW().getAffineY());
    byte[] out = new byte[65];
    out[0] = 0x04;
    System.arraycopy(x, 0, out, 1, 32);
    System.arraycopy(y, 0, out, 33, 32);
    return out;
  }

  private static byte[] unsigned32(BigInteger n) {
    byte[] raw = n.toByteArray();
    if (raw.length == 32) {
      return raw;
    }
    byte[] out = new byte[32];
    if (raw.length == 33 && raw[0] == 0) {
      System.arraycopy(raw, 1, out, 0, 32);
    } else if (raw.length < 32) {
      System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
    } else {
      throw new IllegalArgumentException("EC coordinate too large: " + raw.length + " bytes");
    }
    return out;
  }

  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
