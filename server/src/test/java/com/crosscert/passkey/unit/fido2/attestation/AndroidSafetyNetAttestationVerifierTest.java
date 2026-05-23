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

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  // -----------------------------------------------------------------------------------
  // SafetyNetFixture: package-private record, inlined here.
  // Builds a self-consistent android-safetynet attestation object for testing.
  // -----------------------------------------------------------------------------------

  record SafetyNetFixture(byte[] attestationObject, byte[] clientDataJson) {

    /** Valid fixture with correct nonce, ctsProfileMatch=true, SAN=attest.android.com. */
    static SafetyNetFixture valid(String rpId) throws Exception {
      return build("attest.android.com", true, true, rpId);
    }

    /** Fixture with the nonce last byte XOR'd — nonce mismatch. */
    static SafetyNetFixture withTamperedNonce(String rpId) throws Exception {
      return build("attest.android.com", true, true, rpId, true);
    }

    /** Fixture with ctsProfileMatch overridden to the given value. */
    static SafetyNetFixture withCtsProfileMatch(boolean ctsProfileMatch, String rpId)
        throws Exception {
      return build("attest.android.com", ctsProfileMatch, true, rpId);
    }

    /** Fixture with a custom leaf SAN (not attest.android.com). */
    static SafetyNetFixture withLeafSan(String leafSan, String rpId) throws Exception {
      return build(leafSan, true, true, rpId);
    }

    private static SafetyNetFixture build(
        String leafSan, boolean ctsProfileMatch, boolean basicIntegrity, String rpId)
        throws Exception {
      return build(leafSan, ctsProfileMatch, basicIntegrity, rpId, false);
    }

    private static SafetyNetFixture build(
        String leafSan,
        boolean ctsProfileMatch,
        boolean basicIntegrity,
        String rpId,
        boolean tamperNonce)
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

      // 6. RSA-2048 self-signed leaf cert with SAN dNSName=leafSan.
      KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
      rsaGen.initialize(2048);
      KeyPair rsaPair = rsaGen.generateKeyPair();
      X509Certificate leafCert = buildRsaLeafCert(rsaPair, leafSan);

      // 7. Build JWS (nimbus RS256): header alg=RS256, x5c=[leaf]; payload JSON.
      Map<String, Object> payloadMap = new LinkedHashMap<>();
      payloadMap.put("nonce", nonce);
      payloadMap.put("ctsProfileMatch", ctsProfileMatch);
      payloadMap.put("basicIntegrity", basicIntegrity);
      payloadMap.put("timestampMs", System.currentTimeMillis());

      JWSHeader jwsHeader =
          new JWSHeader.Builder(JWSAlgorithm.RS256)
              .x509CertChain(List.of(Base64.encode(leafCert.getEncoded())))
              .build();

      // Serialize payload as JSON string manually to avoid Jackson dependency in test path.
      String payloadJson = mapToJson(payloadMap);
      JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payloadJson));
      jwsObject.sign(new RSASSASigner((RSAPrivateKey) rsaPair.getPrivate()));
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
     * Build a self-signed RSA-2048 leaf cert with SAN dNSName set to {@code san} and subject
     * CN="SafetyNet Test Leaf". Basic Constraints CA=false.
     */
    private static X509Certificate buildRsaLeafCert(KeyPair rsaPair, String san) throws Exception {
      Instant now = Instant.now();
      X500Name subject = new X500Name("CN=SafetyNet Test Leaf");
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              subject,
              BigInteger.valueOf(System.nanoTime()),
              Date.from(now.minus(1, ChronoUnit.DAYS)),
              Date.from(now.plus(365, ChronoUnit.DAYS)),
              subject,
              rsaPair.getPublic());
      builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
      builder.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, san)));
      return new JcaX509CertificateConverter()
          .getCertificate(
              builder.build(
                  new JcaContentSignerBuilder("SHA256withRSA").build(rsaPair.getPrivate())));
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
