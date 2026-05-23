package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.FidoU2fAttestationVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class FidoU2fAttestationVerifierTest {

  private final FidoU2fAttestationVerifier verifier = new FidoU2fAttestationVerifier();

  @Test
  void verifies_valid_u2f_attestation_non_strict() throws Exception {
    U2fFixture f = U2fFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), null);

    assertThat(result.format()).isEqualTo("fido-u2f");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void rejects_when_signature_does_not_match() throws Exception {
    U2fFixture f = U2fFixture.withTamperedSignature("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.SIGNATURE_INVALID);
  }

  @Test
  void rejects_non_ec_credential_key() throws Exception {
    U2fFixture f = U2fFixture.withRsaCredentialKey("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_missing_sig() throws Exception {
    U2fFixture f = U2fFixture.withoutSig("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_missing_x5c() throws Exception {
    U2fFixture f = U2fFixture.withoutX5c("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  // ── strict 모드 (3건) ──────────────────────────────────────────────────

  @Test
  void strict_rejects_unknown_aaguid() throws Exception {
    U2fFixture f = U2fFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    var emptySource = new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), emptySource))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.MDS_TRUST_FAILED);
  }

  @Test
  void strict_rejects_revoked_aaguid() throws Exception {
    U2fFixture f = U2fFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    // U2F는 보통 zero AAGUID — fixture가 사용하는 AAGUID에 맞춰 entry 구성.
    // leaf cert를 trust anchor로 사용해 체인 검증이 revoked 체크 이전에 통과하도록 함.
    var aaguid = java.util.UUID.fromString("00000000-0000-0000-0000-000000000000");
    var entry =
        new com.crosscert.passkey.fido2.mds.MetadataEntry(
            aaguid,
            java.util.List.of(f.leafCert()),
            java.util.List.of(com.crosscert.passkey.fido2.mds.StatusReport.REVOKED));
    var source = new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of(entry));

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), source))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.AUTHENTICATOR_REVOKED);
  }

  @Test
  void strict_passes_with_matching_trust_anchor() throws Exception {
    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair caKey = ecGen.generateKeyPair();
    X509Certificate caCert = buildSelfSignedCa(caKey, "CN=U2F Test CA");

    U2fFixture f = U2fFixture.withCa(caKey, caCert, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    var aaguid = java.util.UUID.fromString("00000000-0000-0000-0000-000000000000");
    var entry =
        new com.crosscert.passkey.fido2.mds.MetadataEntry(
            aaguid,
            java.util.List.of(caCert),
            java.util.List.of(com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED));
    var source = new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of(entry));

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), source);

    assertThat(result.format()).isEqualTo("fido-u2f");
    assertThat(result.trustPathPresent()).isTrue();
  }

  // ── helpers ────────────────────────────────────────────────────────────

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static X509Certificate buildSelfSignedCa(KeyPair pair, String dn) throws Exception {
    Instant now = Instant.now();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(dn),
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            new X500Name(dn),
            pair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
  }

  // ── U2fFixture ─────────────────────────────────────────────────────────

  /**
   * Inline test fixture record for {@code fido-u2f} attestation. Builds a self-consistent
   * attestation object: EC P-256 credential key, zero AAGUID (U2F convention), self-signed leaf
   * cert, and a correct ECDSA signature over the fido-u2f signed data buffer.
   *
   * <p>Will be extracted to {@code AttestationTestCerts} in Task 5.
   */
  record U2fFixture(byte[] attestationObject, byte[] clientDataJson, X509Certificate leafCert) {

    /** Valid fixture with a correct signature and self-signed EC P-256 leaf. */
    static U2fFixture valid(String rpId) throws Exception {
      return build(rpId, false, false, false, false, null, null);
    }

    /** Fixture with the last byte of the signature XOR'd — signature mismatch. */
    static U2fFixture withTamperedSignature(String rpId) throws Exception {
      return build(rpId, true, false, false, false, null, null);
    }

    /**
     * Fixture with an RSA-2048 credential key in place of EC P-256. The verifier rejects it before
     * attempting to encode the U2F public key, since the cast to ECPublicKey fails.
     */
    static U2fFixture withRsaCredentialKey(String rpId) throws Exception {
      return build(rpId, false, true, false, false, null, null);
    }

    /** Fixture with the {@code sig} entry omitted from attStmt. */
    static U2fFixture withoutSig(String rpId) throws Exception {
      return build(rpId, false, false, true, false, null, null);
    }

    /** Fixture with the {@code x5c} entry omitted from attStmt. */
    static U2fFixture withoutX5c(String rpId) throws Exception {
      return build(rpId, false, false, false, true, null, null);
    }

    /**
     * Fixture where the leaf cert was signed by {@code caPair}/{@code caCert} instead of being
     * self-signed. Register {@code caCert} as the MDS trust anchor to make the strict-mode chain
     * validation pass.
     */
    static U2fFixture withCa(KeyPair caPair, X509Certificate caCert, String rpId) throws Exception {
      return build(rpId, false, false, false, false, caPair, caCert);
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    private static U2fFixture build(
        String rpId,
        boolean tamperSignature,
        boolean rsaCredentialKey,
        boolean omitSig,
        boolean omitX5c,
        KeyPair caKeyPair,
        X509Certificate caCert)
        throws Exception {

      // 1. Credential key pair — EC P-256 (default) or RSA-2048 (non-EC test).
      KeyPair credentialPair;
      byte[] coseKeyBytes;
      if (rsaCredentialKey) {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        credentialPair = rsaGen.generateKeyPair();
        // Build RSA COSE_Key: kty=3, alg=-257, n, e.
        java.security.interfaces.RSAPublicKey rsaPub =
            (java.security.interfaces.RSAPublicKey) credentialPair.getPublic();
        Map<Object, Object> coseMap = new LinkedHashMap<>();
        coseMap.put(1L, 3L); // kty = RSA
        coseMap.put(3L, -257L); // alg = RS256
        coseMap.put(-1L, stripLeadingZero(rsaPub.getModulus().toByteArray())); // n
        coseMap.put(-2L, rsaPub.getPublicExponent().toByteArray()); // e
        coseKeyBytes = CborTestEncoder.encodeMap(coseMap);
      } else {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        credentialPair = ecGen.generateKeyPair();
        ECPublicKey ecPub = (ECPublicKey) credentialPair.getPublic();
        Map<Object, Object> coseMap = new LinkedHashMap<>();
        coseMap.put(1L, 2L); // kty = EC2
        coseMap.put(3L, -7L); // alg = ES256
        coseMap.put(-1L, 1L); // crv = P-256
        coseMap.put(-2L, coordinate(ecPub.getW().getAffineX())); // x
        coseMap.put(-3L, coordinate(ecPub.getW().getAffineY())); // y
        coseKeyBytes = CborTestEncoder.encodeMap(coseMap);
      }

      // 2. authData: rpIdHash(32) | flags 0x45 (UP|UV|AT) | signCount(4=0) | aaguid(16) |
      //              credIdLen(2) | credId(16) | COSE_Key.
      byte[] rpIdHash =
          MessageDigest.getInstance("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
      byte[] aaguid = new byte[16]; // all-zeros (U2F convention)
      byte[] credId = new byte[16]; // all-zeros for fixture simplicity
      ByteArrayOutputStream authDataOut = new ByteArrayOutputStream();
      authDataOut.writeBytes(rpIdHash);
      authDataOut.write(0x45); // UP | UV | AT
      authDataOut.write(0);
      authDataOut.write(0);
      authDataOut.write(0);
      authDataOut.write(0); // signCount = 0
      authDataOut.writeBytes(aaguid);
      authDataOut.write(0);
      authDataOut.write(credId.length); // credIdLen big-endian 2 bytes
      authDataOut.writeBytes(credId);
      authDataOut.writeBytes(coseKeyBytes);
      byte[] authDataBytes = authDataOut.toByteArray();

      // 3. clientDataJSON.
      String clientDataStr =
          "{\"type\":\"webauthn.create\","
              + "\"challenge\":\"Y2hhbGxlbmdl\","
              + "\"origin\":\"https://"
              + rpId
              + "\","
              + "\"crossOrigin\":false}";
      byte[] clientDataJson = clientDataStr.getBytes(StandardCharsets.UTF_8);
      byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);

      // 4. Leaf cert (EC P-256 self-signed, or CA-signed if caKeyPair is provided).
      //    Even for the RSA credential key fixture we use an EC leaf cert to isolate
      //    the "non-EC credential key" error path from x5c/sig issues.
      KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
      ecGen.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair leafPair = ecGen.generateKeyPair();
      X509Certificate leafCert;
      if (caKeyPair != null) {
        leafCert = buildCaSignedLeafCert(leafPair, caKeyPair, caCert);
      } else {
        leafCert = buildSelfSignedLeafCert(leafPair);
      }

      // 5. publicKeyU2F = 0x04 || x(32) || y(32) from EC credential key.
      //    For RSA fixtures, we still need something to compute signedData with; the verifier
      //    rejects the RSA key before reaching the signature check so the bytes here don't matter.
      byte[] publicKeyU2F;
      if (rsaCredentialKey) {
        publicKeyU2F = new byte[65]; // placeholder — verifier never reaches this
      } else {
        ECPublicKey ecPub = (ECPublicKey) credentialPair.getPublic();
        publicKeyU2F = encodeU2fPublicKey(ecPub);
      }

      // 6. signedData = 0x00 || rpIdHash || clientDataHash || credId || publicKeyU2F.
      ByteArrayOutputStream signedDataOut = new ByteArrayOutputStream();
      signedDataOut.write(0x00);
      signedDataOut.writeBytes(rpIdHash);
      signedDataOut.writeBytes(clientDataHash);
      signedDataOut.writeBytes(credId);
      signedDataOut.writeBytes(publicKeyU2F);
      byte[] signedData = signedDataOut.toByteArray();

      // 7. Sign with leaf private key (ECDSA P-256 — matches the leaf cert's public key type).
      Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(leafPair.getPrivate());
      signer.update(signedData);
      byte[] signature = signer.sign();

      if (tamperSignature) {
        signature[signature.length - 1] ^= (byte) 0xff;
      }

      // 8. Build CBOR attestation object.
      Map<Object, Object> attStmt = new LinkedHashMap<>();
      if (!omitSig) {
        attStmt.put("sig", signature);
      }
      if (!omitX5c) {
        List<Object> x5cList;
        if (caKeyPair != null) {
          x5cList = List.of(leafCert.getEncoded(), caCert.getEncoded());
        } else {
          x5cList = List.of(leafCert.getEncoded());
        }
        attStmt.put("x5c", x5cList);
      }

      Map<Object, Object> aoMap = new LinkedHashMap<>();
      aoMap.put("fmt", "fido-u2f");
      aoMap.put("attStmt", attStmt);
      aoMap.put("authData", authDataBytes);
      byte[] attestationObject = CborTestEncoder.encodeMap(aoMap);

      return new U2fFixture(attestationObject, clientDataJson, leafCert);
    }

    // ── cert builders ─────────────────────────────────────────────────────

    private static X509Certificate buildSelfSignedLeafCert(KeyPair pair) throws Exception {
      Instant now = Instant.now();
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              new X500Name("CN=U2F Test Leaf"),
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              new X500Name("CN=U2F Test Leaf"),
              pair.getPublic());
      builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
      return new JcaX509CertificateConverter()
          .getCertificate(
              builder.build(
                  new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    private static X509Certificate buildCaSignedLeafCert(
        KeyPair leafPair, KeyPair caPair, X509Certificate caCert) throws Exception {
      Instant now = Instant.now();
      X500Name issuerDn = new X500Name(caCert.getSubjectX500Principal().getName());
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              issuerDn,
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              new X500Name("CN=U2F Test Leaf"),
              leafPair.getPublic());
      builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
      return new JcaX509CertificateConverter()
          .getCertificate(
              builder.build(
                  new JcaContentSignerBuilder("SHA256withECDSA").build(caPair.getPrivate())));
    }

    // ── key encoding helpers ──────────────────────────────────────────────

    private static byte[] encodeU2fPublicKey(ECPublicKey pub) {
      byte[] x = coordinate(pub.getW().getAffineX());
      byte[] y = coordinate(pub.getW().getAffineY());
      byte[] out = new byte[65];
      out[0] = 0x04;
      System.arraycopy(x, 0, out, 1, 32);
      System.arraycopy(y, 0, out, 33, 32);
      return out;
    }

    private static byte[] coordinate(BigInteger v) {
      byte[] raw = v.toByteArray();
      byte[] out = new byte[32];
      if (raw.length > 32) {
        System.arraycopy(raw, raw.length - 32, out, 0, 32);
      } else {
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
      }
      return out;
    }

    /** Strip leading 0x00 sign byte from RSA modulus byte array if present. */
    private static byte[] stripLeadingZero(byte[] bytes) {
      if (bytes.length > 0 && bytes[0] == 0) {
        byte[] stripped = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, stripped, 0, stripped.length);
        return stripped;
      }
      return bytes;
    }
  }
}
