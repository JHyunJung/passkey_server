package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AppleAnonymousAttestationVerifier;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class AppleAttestationVerifierTest {

  private static final String APPLE_NONCE_OID = "1.2.840.113635.100.8.2";

  @Test
  void verifies_valid_apple_attestation() throws Exception {
    Fixture f = Fixture.valid();
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    AttestationResult result =
        new AppleAnonymousAttestationVerifier().verify(obj, f.clientDataHash, null);
    assertThat(result.format()).isEqualTo("apple");
  }

  @Test
  void rejects_apple_attestation_with_wrong_nonce() throws Exception {
    Fixture f = Fixture.withWrongNonce();
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    assertThatThrownBy(
            () -> new AppleAnonymousAttestationVerifier().verify(obj, f.clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_apple_attestation_missing_x5c() throws Exception {
    Fixture f = Fixture.missingX5c();
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    assertThatThrownBy(
            () -> new AppleAnonymousAttestationVerifier().verify(obj, f.clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void strict_apple_attestation_passes_with_trusted_anchor() throws Exception {
    Fixture f = Fixture.valid();
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    // The fixture cert is self-signed; register itself as the trust anchor for the AAGUID.
    java.util.UUID aaguid = aaguidOfAttestation(obj);
    java.security.cert.X509Certificate selfCert = leafOf(obj);
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource source =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(
            java.util.List.of(
                new com.crosscert.passkey.fido2.mds.MetadataEntry(
                    aaguid,
                    java.util.List.of(selfCert),
                    java.util.List.of(
                        com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED))));
    AttestationResult result =
        new AppleAnonymousAttestationVerifier().verify(obj, f.clientDataHash, source);
    assertThat(result.format()).isEqualTo("apple");
    assertThat(result.trustPathPresent()).isTrue();
  }

  @Test
  void strict_apple_attestation_rejects_untrusted_chain() throws Exception {
    Fixture f = Fixture.valid();
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    // Register an unrelated CA as the trust anchor — PKIX validation must fail.
    java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("EC");
    gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.KeyPair otherPair = gen.generateKeyPair();
    java.security.cert.X509Certificate unrelatedRoot =
        Fixture.selfSignedCa(otherPair, "CN=Unrelated Root");
    java.util.UUID aaguid = aaguidOfAttestation(obj);
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource source =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(
            java.util.List.of(
                new com.crosscert.passkey.fido2.mds.MetadataEntry(
                    aaguid,
                    java.util.List.of(unrelatedRoot),
                    java.util.List.of(
                        com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED))));
    assertThatThrownBy(
            () -> new AppleAnonymousAttestationVerifier().verify(obj, f.clientDataHash, source))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.TRUST_PATH_INVALID);
  }

  // ----- Test helpers ---------------------------------------------------------------------------

  private static java.util.UUID aaguidOfAttestation(AttestationObject obj) {
    byte[] aaguidBytes = obj.authenticatorData().attestedCredentialData().aaguid();
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(aaguidBytes);
    return new java.util.UUID(buf.getLong(), buf.getLong());
  }

  private static java.security.cert.X509Certificate leafOf(AttestationObject obj) throws Exception {
    byte[] certDer = (byte[]) ((java.util.List<?>) obj.attestationStatement().get("x5c")).get(0);
    return (java.security.cert.X509Certificate)
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(certDer));
  }

  // ----- Fixture builder ---------------------------------------------------------------------

  /**
   * Self-consistent Apple anonymous attestation fixture: an attestation cert whose public key
   * matches the credential public key embedded in authData, and whose Apple nonce extension holds
   * SHA-256(authData || clientDataHash). {@link #withWrongNonce} flips the nonce extension to a
   * different value; {@link #missingX5c} drops the x5c entry from attStmt.
   */
  private record Fixture(byte[] attestationObject, byte[] clientDataHash) {

    static Fixture valid() throws Exception {
      return build(true, true);
    }

    static Fixture withWrongNonce() throws Exception {
      return build(false, true);
    }

    static Fixture missingX5c() throws Exception {
      return build(true, false);
    }

    /**
     * @param correctNonce when false, embed a different nonce in the cert extension
     * @param includeX5c when false, omit the x5c entry from attStmt entirely
     */
    private static Fixture build(boolean correctNonce, boolean includeX5c) throws Exception {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair credentialPair = gen.generateKeyPair();
      ECPublicKey credentialPub = (ECPublicKey) credentialPair.getPublic();

      // authData (rpIdHash 32 + flags UP|UV|AT 0x45 + signCount 4 + aaguid 16 + credIdLen 2 +
      // credId + COSE key).
      byte[] aaguid = new byte[16];
      byte[] credId = new byte[] {1, 2, 3, 4};
      byte[] coseKey = coseKey(credentialPub);
      ByteArrayOutputStream authData = new ByteArrayOutputStream();
      authData.write(new byte[32], 0, 32); // rpIdHash
      authData.write(0x45); // UP | UV | AT
      authData.writeBytes(new byte[] {0, 0, 0, 0});
      authData.writeBytes(aaguid);
      authData.writeBytes(new byte[] {0, (byte) credId.length});
      authData.writeBytes(credId);
      authData.writeBytes(coseKey);
      byte[] authDataBytes = authData.toByteArray();

      byte[] clientDataHash = new byte[32]; // fixed hash for fixture
      ByteArrayOutputStream nonceInput = new ByteArrayOutputStream();
      nonceInput.writeBytes(authDataBytes);
      nonceInput.writeBytes(clientDataHash);
      byte[] expectedNonce = MessageDigest.getInstance("SHA-256").digest(nonceInput.toByteArray());
      byte[] certNonce = correctNonce ? expectedNonce : new byte[expectedNonce.length];

      // Build a cert whose public key matches the credential public key, with the Apple nonce
      // extension carrying the chosen nonce bytes.
      X509Certificate cert = buildAttestationCert(credentialPair, certNonce);

      Map<Object, Object> attStmt = new LinkedHashMap<>();
      if (includeX5c) {
        attStmt.put("x5c", List.<Object>of(cert.getEncoded()));
      }
      Map<Object, Object> obj = new LinkedHashMap<>();
      obj.put("fmt", "apple");
      obj.put("attStmt", attStmt);
      obj.put("authData", authDataBytes);
      return new Fixture(CborTestEncoder.encodeMap(obj), clientDataHash);
    }

    /**
     * Builds a self-signed CA certificate (Basic Constraints CA=true) for use as a strict-mode
     * trust anchor in {@link
     * AppleAttestationVerifierTest#strict_apple_attestation_rejects_untrusted_chain}.
     */
    static X509Certificate selfSignedCa(KeyPair pair, String dn) throws Exception {
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
              builder.build(
                  new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    private static X509Certificate buildAttestationCert(KeyPair pair, byte[] nonceBytes)
        throws Exception {
      Instant now = Instant.now();
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              new X500Name("CN=Apple Test Attestation"),
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              new X500Name("CN=Apple Test Attestation"),
              pair.getPublic());
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
      // Apple anonymous attestation nonce extension: SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
      DERSequence sequence =
          new DERSequence(new DERTaggedObject(true, 1, new DEROctetString(nonceBytes)));
      builder.addExtension(new ASN1ObjectIdentifier(APPLE_NONCE_OID), false, sequence.getEncoded());
      return new JcaX509CertificateConverter()
          .getCertificate(
              builder.build(
                  new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    private static byte[] coseKey(ECPublicKey pub) {
      Map<Object, Object> m = new LinkedHashMap<>();
      m.put(1L, 2L);
      m.put(3L, -7L);
      m.put(-1L, 1L);
      m.put(-2L, coordinate(pub.getW().getAffineX()));
      m.put(-3L, coordinate(pub.getW().getAffineY()));
      return CborTestEncoder.encodeMap(m);
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
  }
}
