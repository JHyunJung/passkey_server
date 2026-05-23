package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AndroidKeyAttestationVerifier;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class AndroidKeyAttestationVerifierTest {

  private static final String ANDROID_KEY_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";

  @Test
  void verifies_valid_android_key_attestation() throws Exception {
    Fixture f = Fixture.build(true /* matching challenge */, true /* valid signature */);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    AttestationResult result =
        new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, null);
    assertThat(result.format()).isEqualTo("android-key");
  }

  @Test
  void rejects_android_key_with_invalid_signature() throws Exception {
    Fixture f = Fixture.build(true, false /* signature over garbage */);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_android_key_with_wrong_attestation_challenge() throws Exception {
    Fixture f = Fixture.build(false /* mismatched challenge */, true);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void strict_android_key_attestation_passes_with_trusted_anchor() throws Exception {
    Fixture f = Fixture.build(true, true);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    UUID aaguid = aaguidOfAttestation(obj);
    X509Certificate selfCert = leafOf(obj);
    MdsTrustAnchorSource source =
        new MdsTrustAnchorSource(
            List.of(
                new MetadataEntry(
                    aaguid, List.of(selfCert), List.of(StatusReport.FIDO_CERTIFIED))));
    AttestationResult result =
        new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, source);
    assertThat(result.format()).isEqualTo("android-key");
    assertThat(result.trustPathPresent()).isTrue();
  }

  @Test
  void strict_android_key_attestation_rejects_untrusted_chain() throws Exception {
    Fixture f = Fixture.build(true, true);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair otherPair = gen.generateKeyPair();
    X509Certificate unrelatedRoot = selfSignedCa(otherPair, "CN=Unrelated Root");
    UUID aaguid = aaguidOfAttestation(obj);
    MdsTrustAnchorSource source =
        new MdsTrustAnchorSource(
            List.of(
                new MetadataEntry(
                    aaguid, List.of(unrelatedRoot), List.of(StatusReport.FIDO_CERTIFIED))));
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, source))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.TRUST_PATH_INVALID);
  }

  @Test
  void strict_android_key_attestation_rejects_unknown_aaguid() throws Exception {
    Fixture f = Fixture.build(true, true);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    // empty source — no entries at all → MDS_TRUST_FAILED
    MdsTrustAnchorSource empty = new MdsTrustAnchorSource(List.of());
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, empty))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.MDS_TRUST_FAILED);
  }

  @Test
  void strict_android_key_attestation_rejects_revoked_authenticator() throws Exception {
    Fixture f = Fixture.build(true, true);
    AttestationObject obj = AttestationObject.parse(f.attestationObject);
    UUID aaguid = aaguidOfAttestation(obj);
    X509Certificate selfCert = leafOf(obj);
    MdsTrustAnchorSource revokedSource =
        new MdsTrustAnchorSource(
            List.of(new MetadataEntry(aaguid, List.of(selfCert), List.of(StatusReport.REVOKED))));
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, f.clientDataHash, revokedSource))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.AUTHENTICATOR_REVOKED);
  }

  // ----- Test helpers ---------------------------------------------------------------------------

  private static UUID aaguidOfAttestation(AttestationObject obj) {
    byte[] aaguidBytes = obj.authenticatorData().attestedCredentialData().aaguid();
    ByteBuffer buf = ByteBuffer.wrap(aaguidBytes);
    return new UUID(buf.getLong(), buf.getLong());
  }

  private static X509Certificate leafOf(AttestationObject obj) throws Exception {
    byte[] certDer = (byte[]) ((List<?>) obj.attestationStatement().get("x5c")).get(0);
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certDer));
  }

  private static X509Certificate selfSignedCa(KeyPair pair, String dn) throws Exception {
    return AttestationTestCerts.selfSignedCa(pair, dn);
  }

  // ----- Fixture builder (Apple 패턴 재사용) ---------------------------------------------------

  private record Fixture(byte[] attestationObject, byte[] clientDataHash) {

    static Fixture build(boolean matchingChallenge, boolean validSignature) throws Exception {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair credentialPair = gen.generateKeyPair();
      ECPublicKey credentialPub = (ECPublicKey) credentialPair.getPublic();

      // authData: rpIdHash 32 + flags UP|UV|AT 0x45 + signCount 4 + aaguid 16 + credIdLen 2 +
      // credId + COSE key.
      byte[] aaguid = new byte[16];
      byte[] credId = new byte[] {1, 2, 3, 4};
      byte[] coseKey = coseKey(credentialPub);
      ByteArrayOutputStream authData = new ByteArrayOutputStream();
      authData.write(new byte[32], 0, 32);
      authData.write(0x45);
      authData.writeBytes(new byte[] {0, 0, 0, 0});
      authData.writeBytes(aaguid);
      authData.writeBytes(new byte[] {0, (byte) credId.length});
      authData.writeBytes(credId);
      authData.writeBytes(coseKey);
      byte[] authDataBytes = authData.toByteArray();

      byte[] clientDataHash = new byte[32];
      byte[] certChallenge = matchingChallenge ? clientDataHash : new byte[] {(byte) 0xff};

      // Build attestation cert with KeyDescription extension carrying certChallenge.
      X509Certificate cert = buildAttestationCert(credentialPair, certChallenge);

      // Signature over authData || clientDataHash.
      ByteArrayOutputStream signedDataOut = new ByteArrayOutputStream();
      signedDataOut.writeBytes(authDataBytes);
      signedDataOut.writeBytes(clientDataHash);
      Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(credentialPair.getPrivate());
      signer.update(
          validSignature
              ? signedDataOut.toByteArray()
              : "garbage".getBytes(StandardCharsets.UTF_8));
      byte[] sig = signer.sign();

      Map<Object, Object> attStmt = new LinkedHashMap<>();
      attStmt.put("alg", -7L);
      attStmt.put("sig", sig);
      attStmt.put("x5c", List.<Object>of(cert.getEncoded()));

      Map<Object, Object> obj = new LinkedHashMap<>();
      obj.put("fmt", "android-key");
      obj.put("attStmt", attStmt);
      obj.put("authData", authDataBytes);
      return new Fixture(CborTestEncoder.encodeMap(obj), clientDataHash);
    }

    private static X509Certificate buildAttestationCert(KeyPair pair, byte[] attestationChallenge)
        throws Exception {
      Instant now = Instant.now();
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              new X500Name("CN=Android Key Attestation Test"),
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              new X500Name("CN=Android Key Attestation Test"),
              pair.getPublic());
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

      // KeyDescription SEQUENCE per Android Keystore key attestation spec.
      // Indices: 0 attestationVersion / 1 attestationSecurityLevel / 2 keymasterVersion
      //          / 3 keymasterSecurityLevel / 4 attestationChallenge / 5 uniqueId
      //          / 6 softwareEnforced / 7 teeEnforced.
      ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1Integer(0));
      v.add(new ASN1Enumerated(0));
      v.add(new ASN1Integer(0));
      v.add(new ASN1Enumerated(0));
      v.add(new DEROctetString(attestationChallenge));
      v.add(new DEROctetString(new byte[0]));
      v.add(new DERSequence());
      v.add(new DERSequence());
      DERSequence keyDescription = new DERSequence(v);

      builder.addExtension(
          new ASN1ObjectIdentifier(ANDROID_KEY_EXTENSION_OID), false, keyDescription.getEncoded());
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
