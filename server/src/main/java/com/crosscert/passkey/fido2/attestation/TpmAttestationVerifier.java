package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.tpm.TpmException;
import com.crosscert.passkey.fido2.tpm.TpmsAttest;
import com.crosscert.passkey.fido2.tpm.TpmtPublic;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code tpm} attestation format (WebAuthn L3 §8.3). Only TPM 2.0 (attStmt.ver == "2.0") is
 * supported — TPM 1.2 is rejected with {@code INVALID_ATTESTATION_FORMAT}. Verification (6 steps):
 *
 * <ol>
 *   <li>Extract required attStmt fields (ver=2.0, alg, x5c, sig, certInfo, pubArea).
 *   <li>Parse pubArea (TPMT_PUBLIC) and verify the reconstructed public key equals the credential
 *       public key (by JCA {@code PublicKey.equals}).
 *   <li>Parse certInfo (TPMS_ATTEST) and verify magic, type, extraData == SHA-256(authData ||
 *       clientDataHash), and attested.name == SHA-256-prefixed name of pubArea.
 *   <li>Verify sig over certInfo with the AIK certificate's public key.
 *   <li>Verify AIK certificate is a TPM AIK (v3, basicConstraints CA=false, EKU includes
 *       2.23.133.8.3, SAN includes 2.23.133.2.1/2/3 OIDs, AAGUID extension matches if present).
 *   <li>Strict mode: validate the chain to an MDS trust anchor.
 * </ol>
 */
public final class TpmAttestationVerifier implements AttestationVerifier {

  /** AIK Extended Key Usage OID — id-tcg-kp-AIKCertificate. */
  private static final String TPM_AIK_EKU_OID = "2.23.133.8.3";

  /** SAN OID prefix for TPM-issued certs: 2.23.133.2.{1,2,3} = manufacturer/model/version. */
  private static final String TPM_SAN_OID_PREFIX = "2.23.133.2.";

  /** id-fido-gen-ce-aaguid — same extension as packed format's AAGUID check. */
  private static final String FIDO_AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4";

  @Override
  public String format() {
    return "tpm";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();

      // (1) attStmt required fields + ver=2.0.
      Object verObj = attStmt.get("ver");
      if (!"2.0".equals(verObj)) {
        throw new Fido2VerificationException(
            FailureReason.INVALID_ATTESTATION_FORMAT,
            "tpm attestation ver must be \"2.0\" (got " + verObj + ")");
      }
      Object sigObj = attStmt.get("sig");
      Object algObj = attStmt.get("alg");
      Object x5cObj = attStmt.get("x5c");
      Object certInfoObj = attStmt.get("certInfo");
      Object pubAreaObj = attStmt.get("pubArea");
      if (!(sigObj instanceof byte[] signature)
          || !(algObj instanceof Long algValue)
          || !(x5cObj instanceof List<?> x5cList)
          || x5cList.isEmpty()
          || !(x5cList.get(0) instanceof byte[] aikDer)
          || !(certInfoObj instanceof byte[] certInfo)
          || !(pubAreaObj instanceof byte[] pubArea)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "tpm attStmt missing required field(s)");
      }

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL, "tpm attestation has no attested credential");
      }

      // (2) pubArea ↔ credential public key.
      TpmtPublic pub;
      try {
        pub = TpmtPublic.parse(pubArea);
      } catch (TpmException e) {
        throw new Fido2VerificationException(
            FailureReason.INVALID_TPM_STRUCTURE, "tpm pubArea: " + e.getMessage());
      }
      if (!pub.publicKey().equals(acd.coseKey().publicKey())) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm pubArea public key does not match credential public key");
      }

      // (3) certInfo: parse and verify extraData + attested name.
      TpmsAttest attest;
      try {
        attest = TpmsAttest.parse(certInfo);
      } catch (TpmException e) {
        throw new Fido2VerificationException(
            FailureReason.INVALID_TPM_STRUCTURE, "tpm certInfo: " + e.getMessage());
      }

      // extraData == SHA-256(authData || clientDataHash)
      ByteArrayOutputStream hashInput = new ByteArrayOutputStream();
      hashInput.writeBytes(attestationObject.authenticatorData().rawBytes());
      hashInput.writeBytes(clientDataHash);
      byte[] expectedExtraData =
          MessageDigest.getInstance("SHA-256").digest(hashInput.toByteArray());
      if (!MessageDigest.isEqual(attest.extraData(), expectedExtraData)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm certInfo extraData does not match SHA-256(authData || clientDataHash)");
      }

      // attested.name == nameAlg (2B BE) || SHA-<nameAlg>(pubArea)
      // TPM_ALG_SHA256 = 0x000B → SHA-256
      byte[] expectedAttestedName = computeAttestedName(pub.nameAlg(), pubArea);
      if (!MessageDigest.isEqual(attest.attestedName(), expectedAttestedName)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm certInfo attested.name does not match pubArea hash");
      }

      // (4) Verify sig over certInfo with AIK certificate's public key.
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate aikCert =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(aikDer));
      String jcaAlg = jcaAlgorithmForCoseAlg(algValue);
      Signature verifier = Signature.getInstance(jcaAlg);
      verifier.initVerify(aikCert.getPublicKey());
      verifier.update(certInfo);
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.SIGNATURE_INVALID, "tpm attestation signature over certInfo is invalid");
      }

      // (5) AIK certificate requirements per WebAuthn L3 §8.3.
      verifyAikCertificate(aikCert, acd);

      // (6) Strict mode: validate the chain to an MDS trust anchor.
      if (trustAnchors != null) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Object o : x5cList) {
          if (!(o instanceof byte[] der)) {
            throw new Fido2VerificationException(
                FailureReason.ATTESTATION_INVALID,
                "tpm x5c element must be a DER-encoded certificate");
          }
          chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — tpm authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "tpm authenticator AAGUID " + aaguid + " is revoked or compromised per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "tpm chain does not validate to an MDS trust anchor");
        }
      }

      return new AttestationResult("tpm", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "tpm attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Compute the TPM attested name = nameAlg (2B big-endian) || Hash(pubArea), where the hash
   * algorithm is determined by nameAlg. Only TPM_ALG_SHA256 (0x000B) is supported — the only
   * nameAlg used by WebAuthn tpm authenticators in practice.
   */
  private static byte[] computeAttestedName(int nameAlg, byte[] pubArea)
      throws Fido2VerificationException, GeneralSecurityException {
    String hashAlg =
        switch (nameAlg) {
          case 0x000B -> "SHA-256";
          case 0x000C -> "SHA-384";
          case 0x000D -> "SHA-512";
          default ->
              throw new Fido2VerificationException(
                  FailureReason.INVALID_TPM_STRUCTURE,
                  "tpm pubArea unsupported nameAlg 0x" + Integer.toHexString(nameAlg));
        };
    byte[] hash = MessageDigest.getInstance(hashAlg).digest(pubArea);
    ByteBuffer name = ByteBuffer.allocate(2 + hash.length);
    name.putShort((short) nameAlg);
    name.put(hash);
    return name.array();
  }

  /**
   * Verify AIK certificate requirements per WebAuthn L3 §8.3:
   *
   * <ul>
   *   <li>Version 3 (X.509 v3)
   *   <li>Basic Constraints: CA=false
   *   <li>Extended Key Usage includes id-tcg-kp-AIKCertificate (2.23.133.8.3)
   *   <li>Subject Alternative Name includes at least one TPM SAN OID (2.23.133.2.{1,2,3})
   *   <li>If FIDO AAGUID extension is present, it matches the credential's AAGUID
   * </ul>
   */
  private static void verifyAikCertificate(X509Certificate cert, AttestedCredentialData acd)
      throws Fido2VerificationException {
    // X.509 v3
    if (cert.getVersion() != 3) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "tpm AIK cert is not X.509 version 3: v" + cert.getVersion());
    }

    // Basic Constraints: CA=false (getBasicConstraints returns -1 for non-CA)
    if (cert.getBasicConstraints() != -1) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert Basic Constraints CA must be false");
    }

    // EKU must include id-tcg-kp-AIKCertificate (2.23.133.8.3)
    List<String> ekuOids;
    try {
      ekuOids = cert.getExtendedKeyUsage();
    } catch (Exception e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert EKU parse failed: " + e.getMessage());
    }
    if (ekuOids == null || !ekuOids.contains(TPM_AIK_EKU_OID)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "tpm AIK cert EKU does not include id-tcg-kp-AIKCertificate (2.23.133.8.3)");
    }

    // SAN must include at least one TPM OID (2.23.133.2.{1,2,3})
    if (!hasTpmSan(cert)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "tpm AIK cert SAN does not include any TPM OID (2.23.133.2.*)");
    }

    // FIDO AAGUID extension — optional; if present must match authData AAGUID
    byte[] certAaguid = fidoAaguidExtension(cert);
    if (certAaguid != null && !Arrays.equals(certAaguid, acd.aaguid())) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "tpm AIK cert AAGUID extension does not match authenticator data AAGUID");
    }
  }

  /**
   * Returns {@code true} if the AIK certificate's Subject Alternative Name contains at least one
   * OtherName entry whose type OID starts with the TCG TPM SAN prefix (2.23.133.2.).
   *
   * <p>The JDK SAN API returns OtherName entries as type=0 with a {@code byte[]} value that is the
   * raw DER encoding of the {@code OtherName} SEQUENCE — i.e. {@code SEQUENCE { OID, [0] EXPLICIT
   * value }}. We parse the OID from the first element of the SEQUENCE using minimal DER parsing (no
   * external dependency).
   */
  private static boolean hasTpmSan(X509Certificate cert) {
    try {
      Collection<List<?>> sans = cert.getSubjectAlternativeNames();
      if (sans == null) {
        return false;
      }
      for (List<?> san : sans) {
        if (san.size() >= 2 && Integer.valueOf(0).equals(san.get(0))) {
          // type=0 is OtherName; the JDK gives us the raw DER bytes of the OtherName SEQUENCE.
          Object value = san.get(1);
          if (value instanceof byte[] raw) {
            try {
              String oid = derOtherNameOid(raw);
              if (oid != null && oid.startsWith(TPM_SAN_OID_PREFIX)) {
                return true;
              }
            } catch (Exception ignored) {
              // Not parseable — skip this entry
            }
          }
        }
      }
    } catch (Exception ignored) {
      // Treat any parse failure as SAN absent → verification will reject
    }
    return false;
  }

  /**
   * Extract the OID string from a DER-encoded OtherName SEQUENCE ({@code SEQUENCE { OID, [0] value
   * }}). Returns {@code null} on any parse failure.
   *
   * <p>DER OID encoding: tag {@code 0x06}, length byte(s), then the OID components encoded in
   * base-128. The first two components are packed as {@code 40*c1 + c2}; subsequent components are
   * base-128 big-endian with high bit set on all but the last byte.
   */
  private static String derOtherNameOid(byte[] otherNameDer) {
    // Outer SEQUENCE: tag 0x30
    if (otherNameDer.length < 2 || (otherNameDer[0] & 0xff) != 0x30) {
      return null;
    }
    int seqLen = derLength(otherNameDer, 1);
    int seqContentOffset = derLengthOffset(otherNameDer, 1);
    if (seqContentOffset < 0 || seqLen < 0) {
      return null;
    }
    // First element must be OID tag 0x06
    int pos = seqContentOffset;
    if (pos >= otherNameDer.length || (otherNameDer[pos] & 0xff) != 0x06) {
      return null;
    }
    pos++;
    int oidLen = derLength(otherNameDer, pos);
    int oidOffset = derLengthOffset(otherNameDer, pos);
    if (oidOffset < 0 || oidLen < 0 || oidOffset + oidLen > otherNameDer.length) {
      return null;
    }
    return decodeOid(otherNameDer, oidOffset, oidLen);
  }

  /**
   * Decode a DER OID body (already past the tag and length bytes) into a dotted string like {@code
   * "2.23.133.2.1"}.
   */
  private static String decodeOid(byte[] der, int offset, int length) {
    if (length == 0) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    // First byte encodes first two components: first = b/40, second = b%40
    int first = (der[offset] & 0xff) / 40;
    int second = (der[offset] & 0xff) % 40;
    sb.append(first).append('.').append(second);
    long component = 0;
    for (int i = 1; i < length; i++) {
      int b = der[offset + i] & 0xff;
      component = (component << 7) | (b & 0x7f);
      if ((b & 0x80) == 0) {
        sb.append('.').append(component);
        component = 0;
      }
    }
    return sb.toString();
  }

  /** Return the value of a DER length field starting at {@code pos}, or -1 on error. */
  private static int derLength(byte[] der, int pos) {
    if (pos >= der.length) {
      return -1;
    }
    int b = der[pos] & 0xff;
    if (b < 0x80) {
      return b;
    } else if (b == 0x81) {
      return (pos + 1 < der.length) ? (der[pos + 1] & 0xff) : -1;
    } else if (b == 0x82) {
      return (pos + 2 < der.length) ? ((der[pos + 1] & 0xff) << 8) | (der[pos + 2] & 0xff) : -1;
    }
    return -1;
  }

  /** Return the byte offset of the content after the DER length field at {@code pos}. */
  private static int derLengthOffset(byte[] der, int pos) {
    if (pos >= der.length) {
      return -1;
    }
    int b = der[pos] & 0xff;
    if (b < 0x80) {
      return pos + 1;
    } else if (b == 0x81) {
      return pos + 2;
    } else if (b == 0x82) {
      return pos + 3;
    }
    return -1;
  }

  /**
   * Extracts the 16-byte AAGUID from the FIDO AAGUID certificate extension (OID
   * 1.3.6.1.4.1.45724.1.1.4), or {@code null} if the extension is absent (optional).
   */
  private static byte[] fidoAaguidExtension(X509Certificate cert)
      throws Fido2VerificationException {
    byte[] raw = cert.getExtensionValue(FIDO_AAGUID_EXTENSION_OID);
    if (raw == null) {
      return null;
    }
    byte[] inner = DerUtil.unwrapOctetString(raw, "FIDO AAGUID extension outer OCTET STRING");
    byte[] aaguid = DerUtil.unwrapOctetString(inner, "FIDO AAGUID extension inner OCTET STRING");
    if (aaguid.length != 16) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "tpm AIK cert AAGUID extension is not 16 bytes: " + aaguid.length);
    }
    return aaguid;
  }

  /**
   * Maps a COSE algorithm identifier to a JCA algorithm name.
   *
   * <p>Only COSE alg values listed in WebAuthn L3 §8.3 for tpm are supported: -7 (ES256) and -257
   * (RS256). RS1 (-65535, SHA1withRSA) is intentionally NOT supported — SHA-1 is cryptographically
   * deprecated and not listed in the spec.
   */
  private static String jcaAlgorithmForCoseAlg(long coseAlg) throws Fido2VerificationException {
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default ->
          throw new Fido2VerificationException(
              FailureReason.UNSUPPORTED_ALGORITHM, "tpm attestation unsupported alg: " + coseAlg);
    };
  }

  /** Decode the 16-byte AAGUID of {@code acd} into a {@link UUID}. */
  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
