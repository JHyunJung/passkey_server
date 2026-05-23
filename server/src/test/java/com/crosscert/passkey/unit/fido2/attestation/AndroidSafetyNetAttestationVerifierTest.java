package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AndroidSafetyNetAttestationVerifier;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class AndroidSafetyNetAttestationVerifierTest {

  private final AndroidSafetyNetAttestationVerifier verifier =
      new AndroidSafetyNetAttestationVerifier();

  @Test
  void verifies_valid_safetynet_attestation_non_strict() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    byte[] clientDataHash = sha256(f.clientDataJson());

    AttestationResult result = verifier.verify(obj, clientDataHash, null);

    assertThat(result.format()).isEqualTo("android-safetynet");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void rejects_when_nonce_does_not_match() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withTamperedNonce("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_cts_profile_match_false() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withCtsProfileMatch(false, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_leaf_cert_san_is_not_attest_android_com() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withLeafSan("evil.example.com", "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  // I2: leaf cert with non-RSA (EC) key — RSAPublicKey cast fails → ATTESTATION_INVALID
  @Test
  void rejects_when_leaf_cert_key_is_not_rsa() throws Exception {
    // EC leaf still has SAN=attest.android.com so the SAN check passes, but the RSA cast fails.
    SafetyNetFixture f =
        SafetyNetFixture.withEcLeaf(
            AndroidSafetyNetAttestationVerifier.EXPECTED_LEAF_SAN, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  // I3: tampered JWS signature → SIGNATURE_INVALID
  @Test
  void rejects_when_jws_signature_invalid() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withTamperedJwsSignature("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.SIGNATURE_INVALID);
  }

  // I4: basicIntegrity=false → ATTESTATION_INVALID
  @Test
  void rejects_when_basic_integrity_false() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withBasicIntegrity(false, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  // I5a: strict mode — unknown AAGUID → MDS_TRUST_FAILED
  @Test
  void strict_rejects_unknown_aaguid() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource empty =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), empty))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.MDS_TRUST_FAILED);
  }

  // I5b: strict mode — revoked AAGUID → AUTHENTICATOR_REVOKED
  @Test
  void strict_rejects_revoked_aaguid() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    UUID aaguid = aaguidOfAttestation(obj);
    // Use the fixture's own leaf cert as the trust anchor cert (chain validates) — but status
    // REVOKED.
    X509Certificate leafCert = safetyNetLeafOf(obj);
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource revokedSource =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(
            java.util.List.of(
                new com.crosscert.passkey.fido2.mds.MetadataEntry(
                    aaguid,
                    java.util.List.of(leafCert),
                    java.util.List.of(com.crosscert.passkey.fido2.mds.StatusReport.REVOKED))));

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), revokedSource))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.AUTHENTICATOR_REVOKED);
  }

  // I5c: strict mode happy path — chain validates to MDS trust anchor → trustPathPresent=true
  @Test
  void strict_passes_with_matching_trust_anchor() throws Exception {
    // Build a CA key pair and use it as both the leaf cert issuer and the MDS trust anchor.
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
    rsaGen.initialize(2048);
    KeyPair caPair = rsaGen.generateKeyPair();
    X509Certificate caCert = buildSelfSignedCa(caPair, "CN=SafetyNet Test CA");

    SafetyNetFixture f = SafetyNetFixture.withCa(caPair, caCert, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    UUID aaguid = aaguidOfAttestation(obj);

    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource source =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(
            java.util.List.of(
                new com.crosscert.passkey.fido2.mds.MetadataEntry(
                    aaguid,
                    java.util.List.of(caCert),
                    java.util.List.of(
                        com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED))));

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), source);
    assertThat(result.format()).isEqualTo("android-safetynet");
    assertThat(result.trustPathPresent()).isTrue();
  }

  // ------ helpers -------------------------------------------------------------------------------

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static UUID aaguidOfAttestation(AttestationObject obj) {
    byte[] aaguidBytes = obj.authenticatorData().attestedCredentialData().aaguid();
    ByteBuffer buf = ByteBuffer.wrap(aaguidBytes);
    return new UUID(buf.getLong(), buf.getLong());
  }

  /**
   * Extract the leaf X.509 certificate from the JWS x5c header of a SafetyNet attestation object.
   * The JWS compact is stored as the {@code response} byte[] in attStmt.
   */
  private static X509Certificate safetyNetLeafOf(AttestationObject obj) throws Exception {
    byte[] responseBytes = (byte[]) obj.attestationStatement().get("response");
    String compact = new String(responseBytes, StandardCharsets.UTF_8);
    JWSObject jws = JWSObject.parse(compact);
    Base64 b64 = jws.getHeader().getX509CertChain().iterator().next();
    return (X509Certificate)
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(b64.decode()));
  }

  private static X509Certificate buildSelfSignedCa(KeyPair pair, String dn) throws Exception {
    return AttestationTestCerts.selfSignedCa(pair, dn);
  }

  // -----------------------------------------------------------------------------------
  // SafetyNetFixture: package-private record, inlined here.
  // Builds a self-consistent android-safetynet attestation object for testing.
  // -----------------------------------------------------------------------------------

  record SafetyNetFixture(byte[] attestationObject, byte[] clientDataJson) {

    /** Valid fixture with correct nonce, ctsProfileMatch=true, SAN=attest.android.com. */
    static SafetyNetFixture valid(String rpId) throws Exception {
      return build(
          AndroidSafetyNetAttestationVerifier.EXPECTED_LEAF_SAN,
          true,
          true,
          rpId,
          false,
          null,
          null);
    }

    /** Fixture with the nonce last byte XOR'd — nonce mismatch. */
    static SafetyNetFixture withTamperedNonce(String rpId) throws Exception {
      return build(
          AndroidSafetyNetAttestationVerifier.EXPECTED_LEAF_SAN,
          true,
          true,
          rpId,
          true,
          null,
          null);
    }

    /** Fixture with ctsProfileMatch overridden to the given value. */
    static SafetyNetFixture withCtsProfileMatch(boolean ctsProfileMatch, String rpId)
        throws Exception {
      return build(
          AndroidSafetyNetAttestationVerifier.EXPECTED_LEAF_SAN,
          ctsProfileMatch,
          true,
          rpId,
          false,
          null,
          null);
    }

    /** Fixture with basicIntegrity overridden to the given value. */
    static SafetyNetFixture withBasicIntegrity(boolean basicIntegrity, String rpId)
        throws Exception {
      return build(
          AndroidSafetyNetAttestationVerifier.EXPECTED_LEAF_SAN,
          true,
          basicIntegrity,
          rpId,
          false,
          null,
          null);
    }

    /** Fixture with a custom leaf SAN (not attest.android.com). */
    static SafetyNetFixture withLeafSan(String leafSan, String rpId) throws Exception {
      return build(leafSan, true, true, rpId, false, null, null);
    }

    /**
     * Fixture with an EC P-256 leaf cert whose SAN is {@code attest.android.com} — the SAN check
     * passes but the {@code (RSAPublicKey)} cast in the verifier fails with ClassCastException,
     * which lands in the outer catch as ATTESTATION_INVALID.
     */
    static SafetyNetFixture withEcLeaf(String leafSan, String rpId) throws Exception {
      return build(leafSan, true, true, rpId, false, null, null, true /* ecLeaf */);
    }

    /**
     * Fixture with a valid JWS whose third dot-separated segment (signature) has one byte mutated —
     * signature verification returns false → SIGNATURE_INVALID.
     */
    static SafetyNetFixture withTamperedJwsSignature(String rpId) throws Exception {
      return buildWithTamperedSignature(rpId);
    }

    /**
     * Fixture where the JWS leaf cert was signed by {@code caPair}/{@code caCert} instead of being
     * self-signed. Use {@code caCert} as the MDS trust anchor to make the strict-mode chain
     * validation pass.
     */
    static SafetyNetFixture withCa(KeyPair caPair, X509Certificate caCert, String rpId)
        throws Exception {
      return build(
          AndroidSafetyNetAttestationVerifier.EXPECTED_LEAF_SAN,
          true,
          true,
          rpId,
          false,
          caPair,
          caCert);
    }

    // ------ private build methods -------------------------------------------------------------

    private static SafetyNetFixture build(
        String leafSan,
        boolean ctsProfileMatch,
        boolean basicIntegrity,
        String rpId,
        boolean tamperNonce,
        KeyPair caKeyPair,
        X509Certificate caCert)
        throws Exception {
      return build(
          leafSan, ctsProfileMatch, basicIntegrity, rpId, tamperNonce, caKeyPair, caCert, false);
    }

    private static SafetyNetFixture build(
        String leafSan,
        boolean ctsProfileMatch,
        boolean basicIntegrity,
        String rpId,
        boolean tamperNonce,
        KeyPair caKeyPair,
        X509Certificate caCert,
        boolean ecLeaf)
        throws Exception {

      // 1. EC P-256 credential key pair.
      KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
      ecGen.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair credentialPair = ecGen.generateKeyPair();
      ECPublicKey credentialPub = (ECPublicKey) credentialPair.getPublic();

      // 2. COSE_Key CBOR: kty=2 (EC), alg=-7 (ES256), crv=1 (P-256), x, y.
      Map<Object, Object> coseMap = new LinkedHashMap<>();
      coseMap.put(1L, 2L);
      coseMap.put(3L, -7L);
      coseMap.put(-1L, 1L);
      coseMap.put(-2L, coordinate(credentialPub.getW().getAffineX()));
      coseMap.put(-3L, coordinate(credentialPub.getW().getAffineY()));
      byte[] coseKeyBytes = CborTestEncoder.encodeMap(coseMap);

      // 3. authData: rpIdHash(32) | flags 0x45 UP|UV|AT | signCount(4) | aaguid(16) |
      //              credIdLen(2) | credId(16) | COSE_Key.
      byte[] rpIdHash =
          MessageDigest.getInstance("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
      byte[] aaguid = new byte[16]; // all-zeros
      byte[] credId = new byte[16]; // 16 random-ish bytes (all zeros for simplicity)
      ByteArrayOutputStream authDataOut = new ByteArrayOutputStream();
      authDataOut.writeBytes(rpIdHash);
      authDataOut.write(0x45); // UP | UV | AT
      authDataOut.write(0);
      authDataOut.write(0);
      authDataOut.write(0);
      authDataOut.write(0); // signCount = 0
      authDataOut.writeBytes(aaguid);
      authDataOut.write(0);
      authDataOut.write(credId.length); // credIdLen
      authDataOut.writeBytes(credId);
      authDataOut.writeBytes(coseKeyBytes);
      byte[] authDataBytes = authDataOut.toByteArray();

      // 4. clientDataJSON.
      String clientDataStr =
          "{\"type\":\"webauthn.create\","
              + "\"challenge\":\"Y2hhbGxlbmdl\","
              + "\"origin\":\"https://"
              + rpId
              + "\","
              + "\"crossOrigin\":false}";
      byte[] clientDataJson = clientDataStr.getBytes(StandardCharsets.UTF_8);

      // 5. clientDataHash and nonce = base64(SHA-256(authData || clientDataHash)).
      byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
      ByteArrayOutputStream nonceInput = new ByteArrayOutputStream();
      nonceInput.writeBytes(authDataBytes);
      nonceInput.writeBytes(clientDataHash);
      byte[] nonceBytes = MessageDigest.getInstance("SHA-256").digest(nonceInput.toByteArray());
      if (tamperNonce) {
        nonceBytes[nonceBytes.length - 1] ^= (byte) 0xff;
      }
      String nonce = java.util.Base64.getEncoder().encodeToString(nonceBytes);

      // 6. Build leaf cert — RSA-2048 by default; EC P-256 if ecLeaf=true.
      List<Base64> x5cList;
      RSAPrivateKey jwsSigningKey;
      if (ecLeaf) {
        // EC leaf: SAN will match attest.android.com but RSAPublicKey cast will throw.
        KeyPairGenerator ecLeafGen = KeyPairGenerator.getInstance("EC");
        ecLeafGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecLeafPair = ecLeafGen.generateKeyPair();
        X509Certificate ecLeafCert = buildEcLeafCert(ecLeafPair, leafSan);
        x5cList = List.of(Base64.encode(ecLeafCert.getEncoded()));
        // We still need an RSA key to sign the JWS header+payload — but the verifier will fail
        // before even checking the signature (ClassCastException on the EC public key).
        // Use a temporary RSA key just to produce a parseable JWS.
        KeyPairGenerator rsaTmp = KeyPairGenerator.getInstance("RSA");
        rsaTmp.initialize(2048);
        KeyPair tmpRsa = rsaTmp.generateKeyPair();
        jwsSigningKey = (RSAPrivateKey) tmpRsa.getPrivate();
      } else if (caKeyPair != null) {
        // CA-signed leaf: leaf private key signs JWS; leaf cert is issued by CA.
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair leafRsaPair = rsaGen.generateKeyPair();
        X509Certificate leafCert = buildCaSignedLeafCert(leafRsaPair, caKeyPair, caCert, leafSan);
        x5cList = List.of(Base64.encode(leafCert.getEncoded()), Base64.encode(caCert.getEncoded()));
        jwsSigningKey = (RSAPrivateKey) leafRsaPair.getPrivate();
      } else {
        // Self-signed RSA-2048 leaf.
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaPair = rsaGen.generateKeyPair();
        X509Certificate leafCert = buildRsaLeafCert(rsaPair, leafSan);
        x5cList = List.of(Base64.encode(leafCert.getEncoded()));
        jwsSigningKey = (RSAPrivateKey) rsaPair.getPrivate();
      }

      // 7. Build JWS (nimbus RS256): header alg=RS256, x5c=[...]; payload JSON.
      Map<String, Object> payloadMap = new LinkedHashMap<>();
      payloadMap.put("nonce", nonce);
      payloadMap.put("ctsProfileMatch", ctsProfileMatch);
      payloadMap.put("basicIntegrity", basicIntegrity);
      payloadMap.put("timestampMs", System.currentTimeMillis());

      JWSHeader jwsHeader =
          new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertChain(x5cList).build();

      String payloadJson = mapToJson(payloadMap);
      JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payloadJson));
      jwsObject.sign(new RSASSASigner(jwsSigningKey));
      byte[] responseBytes = jwsObject.serialize().getBytes(StandardCharsets.UTF_8);

      // 8. attestationObject CBOR: {fmt, attStmt:{ver, response}, authData}.
      Map<Object, Object> attStmt = new LinkedHashMap<>();
      attStmt.put("ver", "19283746");
      attStmt.put("response", responseBytes);

      Map<Object, Object> aoMap = new LinkedHashMap<>();
      aoMap.put("fmt", "android-safetynet");
      aoMap.put("attStmt", attStmt);
      aoMap.put("authData", authDataBytes);
      byte[] attestationObject = CborTestEncoder.encodeMap(aoMap);

      return new SafetyNetFixture(attestationObject, clientDataJson);
    }

    /**
     * Build a fixture identical to {@code valid()} but with one byte of the JWS signature segment
     * (the third dot-separated part) flipped — signature verification returns false.
     */
    private static SafetyNetFixture buildWithTamperedSignature(String rpId) throws Exception {
      // Build valid first to get a clean fixture byte array.
      SafetyNetFixture valid = valid(rpId);
      // Re-parse the attestation object to retrieve the JWS compact string.
      AttestationObject parsed = AttestationObject.parse(valid.attestationObject());
      byte[] responseBytes = (byte[]) parsed.attestationStatement().get("response");
      String compact = new String(responseBytes, StandardCharsets.UTF_8);

      // Mutate one byte in the signature segment (third dot-separated part).
      String[] parts = compact.split("\\.", -1);
      // parts[2] is the Base64URL-encoded signature.
      byte[] sigBytes = parts[2].getBytes(StandardCharsets.UTF_8);
      sigBytes[sigBytes.length / 2] ^= (byte) 0x01; // flip one bit
      String tampered =
          parts[0] + "." + parts[1] + "." + new String(sigBytes, StandardCharsets.UTF_8);

      byte[] tamperedResponseBytes = tampered.getBytes(StandardCharsets.UTF_8);

      // Re-encode attStmt with tampered response.
      Map<Object, Object> attStmt = new LinkedHashMap<>();
      attStmt.put("ver", "19283746");
      attStmt.put("response", tamperedResponseBytes);

      Map<Object, Object> aoMap = new LinkedHashMap<>();
      aoMap.put("fmt", "android-safetynet");
      aoMap.put("attStmt", attStmt);
      aoMap.put("authData", parsed.authenticatorData().rawBytes());
      byte[] attestationObject = CborTestEncoder.encodeMap(aoMap);

      return new SafetyNetFixture(attestationObject, valid.clientDataJson());
    }

    /**
     * Build a self-signed RSA-2048 leaf cert with SAN dNSName set to {@code san} and subject
     * CN="SafetyNet Test Leaf". Basic Constraints CA=false.
     */
    private static X509Certificate buildRsaLeafCert(KeyPair rsaPair, String san) throws Exception {
      return buildRsaLeafCertIssuedBy(rsaPair, rsaPair, null, san);
    }

    /** Build an RSA leaf cert issued and signed by {@code caPair}/{@code caCert}. */
    private static X509Certificate buildCaSignedLeafCert(
        KeyPair leafPair, KeyPair caPair, X509Certificate caCert, String san) throws Exception {
      return buildRsaLeafCertIssuedBy(leafPair, caPair, caCert, san);
    }

    private static X509Certificate buildRsaLeafCertIssuedBy(
        KeyPair leafPair, KeyPair signingPair, X509Certificate issuerCert, String san)
        throws Exception {
      Instant now = Instant.now();
      X500Name subject = new X500Name("CN=SafetyNet Test Leaf");
      X500Name issuerDn =
          issuerCert != null
              ? new X500Name(issuerCert.getSubjectX500Principal().getName())
              : subject;
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              issuerDn,
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              subject,
              leafPair.getPublic());
      builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
      builder.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, san)));
      return new JcaX509CertificateConverter()
          .getCertificate(
              builder.build(
                  new JcaContentSignerBuilder("SHA256withRSA").build(signingPair.getPrivate())));
    }

    /**
     * Build a self-signed EC P-256 leaf cert with SAN dNSName set to {@code san}. The verifier
     * expects RSAPublicKey; the cast will fail → ClassCastException → ATTESTATION_INVALID.
     */
    private static X509Certificate buildEcLeafCert(KeyPair ecPair, String san) throws Exception {
      Instant now = Instant.now();
      X500Name subject = new X500Name("CN=SafetyNet EC Test Leaf");
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              subject,
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              subject,
              ecPair.getPublic());
      builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
      builder.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, san)));
      return new JcaX509CertificateConverter()
          .getCertificate(
              builder.build(
                  new JcaContentSignerBuilder("SHA256withECDSA").build(ecPair.getPrivate())));
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

    /** Minimal JSON serialiser for the fixture payload (avoids Jackson in test). */
    private static String mapToJson(Map<String, Object> map) {
      StringBuilder sb = new StringBuilder("{");
      boolean first = true;
      for (Map.Entry<String, Object> entry : map.entrySet()) {
        if (!first) sb.append(",");
        first = false;
        sb.append("\"").append(entry.getKey()).append("\":");
        Object v = entry.getValue();
        if (v instanceof String s) {
          sb.append("\"").append(s).append("\"");
        } else if (v instanceof Boolean b) {
          sb.append(b);
        } else {
          sb.append(v);
        }
      }
      sb.append("}");
      return sb.toString();
    }
  }
}
