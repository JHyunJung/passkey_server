package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.AttestationVerifiers;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

class AttestationVerifierTest {

  @Test
  void verifies_none_attestation() throws Exception {
    AttestationObject obj = AttestationObject.parse(noneAttestationObject());
    AttestationResult result = AttestationVerifiers.forFormat("none").verify(obj, new byte[32]);
    assertThat(result.format()).isEqualTo("none");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void none_attestation_with_non_empty_statement_is_rejected() {
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("x", 1L);
    AttestationObject obj = AttestationObject.parse(attestationObject("none", attStmt));
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("none").verify(obj, new byte[32]))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void unsupported_format_is_rejected() {
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("tpm"))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UNSUPPORTED_ATTESTATION_FORMAT);
  }

  @Test
  void verifies_packed_self_attestation() throws Exception {
    byte[] clientDataHash = new byte[32];
    AttestationObject obj =
        AttestationObject.parse(packedSelfAttestationObject(clientDataHash, true));
    AttestationResult result = AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash);
    assertThat(result.format()).isEqualTo("packed");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void packed_with_invalid_signature_is_rejected() throws Exception {
    byte[] clientDataHash = new byte[32];
    AttestationObject obj =
        AttestationObject.parse(packedSelfAttestationObject(clientDataHash, false));
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("packed").verify(obj, clientDataHash))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void verifies_packed_full_attestation_with_x5c() throws Exception {
    // x5c full attestation: attestation cert의 개인키로 서명, cert chain trust는 검증 안 함(non-strict).
    byte[] clientDataHash = new byte[32];

    // Generate an EC keypair and self-signed cert for the attestation statement.
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair attPair = gen.generateKeyPair();
    X509Certificate attCert = selfSignedCert(attPair, "CN=Attestation Test");

    // Credential keypair (separate from attestation keypair — full attestation uses cert key).
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair credPair = gen.generateKeyPair();
    ECPublicKey credPub = (ECPublicKey) credPair.getPublic();

    Map<Object, Object> coseMap = new LinkedHashMap<>();
    coseMap.put(1L, 2L);
    coseMap.put(3L, -7L);
    coseMap.put(-1L, 1L);
    coseMap.put(-2L, coordinate(credPub.getW().getAffineX()));
    coseMap.put(-3L, coordinate(credPub.getW().getAffineY()));
    byte[] cose = CborTestEncoder.encodeMap(coseMap);

    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(new byte[32]); // rpIdHash
    authData.write(0x41); // UP | AT
    authData.writeBytes(new byte[] {0, 0, 0, 0}); // signCount
    authData.writeBytes(new byte[16]); // aaguid
    authData.writeBytes(new byte[] {0, 2}); // credIdLen
    authData.writeBytes(new byte[] {1, 2}); // credId
    authData.writeBytes(cose);
    byte[] authDataBytes = authData.toByteArray();

    ByteArrayOutputStream signed = new ByteArrayOutputStream();
    signed.writeBytes(authDataBytes);
    signed.writeBytes(clientDataHash);

    // Sign with the attestation cert's private key (not the credential key).
    java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
    signer.initSign(attPair.getPrivate());
    signer.update(signed.toByteArray());
    byte[] sig = signer.sign();

    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -7L);
    attStmt.put("sig", sig);
    attStmt.put("x5c", List.of(attCert.getEncoded())); // DER-encoded cert

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", authDataBytes);
    AttestationObject attestationObject = AttestationObject.parse(CborTestEncoder.encodeMap(obj));

    AttestationResult result =
        AttestationVerifiers.forFormat("packed").verify(attestationObject, clientDataHash);
    assertThat(result.format()).isEqualTo("packed");
    assertThat(result.trustPathPresent()).isTrue();
  }

  @Test
  void packed_x5c_with_invalid_signature_is_rejected() throws Exception {
    // x5c full attestation with a bad signature — must be rejected.
    byte[] clientDataHash = new byte[32];

    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair attPair = gen.generateKeyPair();
    X509Certificate attCert = selfSignedCert(attPair, "CN=Attestation Test");

    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair credPair = gen.generateKeyPair();
    ECPublicKey credPub = (ECPublicKey) credPair.getPublic();

    Map<Object, Object> coseMap = new LinkedHashMap<>();
    coseMap.put(1L, 2L);
    coseMap.put(3L, -7L);
    coseMap.put(-1L, 1L);
    coseMap.put(-2L, coordinate(credPub.getW().getAffineX()));
    coseMap.put(-3L, coordinate(credPub.getW().getAffineY()));
    byte[] cose = CborTestEncoder.encodeMap(coseMap);

    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(new byte[32]);
    authData.write(0x41);
    authData.writeBytes(new byte[] {0, 0, 0, 0});
    authData.writeBytes(new byte[16]);
    authData.writeBytes(new byte[] {0, 2});
    authData.writeBytes(new byte[] {1, 2});
    authData.writeBytes(cose);
    byte[] authDataBytes = authData.toByteArray();

    // Use garbage bytes as signature.
    byte[] badSig = "notasignature".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -7L);
    attStmt.put("sig", badSig);
    attStmt.put("x5c", List.of(attCert.getEncoded()));

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", authDataBytes);
    AttestationObject attestationObject = AttestationObject.parse(CborTestEncoder.encodeMap(obj));

    assertThatThrownBy(
            () ->
                AttestationVerifiers.forFormat("packed").verify(attestationObject, clientDataHash))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_missing_sig_is_rejected() throws Exception {
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -7L);
    AttestationObject obj = AttestationObject.parse(attestationObject("packed", attStmt));
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("packed").verify(obj, new byte[32]))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void packed_with_alg_mismatch_is_rejected() throws Exception {
    // attStmt.alg를 credential 키의 alg(-7)와 다른 값(-257)으로 — §8.2 alg 일치 검증 위반.
    byte[] clientDataHash = new byte[32];
    // packedSelfAttestationObject가 alg=-7로 만드므로, attStmt만 바꿔 재조립.
    AttestationObject base =
        AttestationObject.parse(packedSelfAttestationObject(clientDataHash, true));
    // base에서 authData를 그대로 쓰고 attStmt.alg만 -257로 바꾼 새 attestationObject 조립.
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -257L);
    attStmt.put("sig", (byte[]) base.attestationStatement().get("sig"));
    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", base.authenticatorData().rawBytes());
    AttestationObject mismatched = AttestationObject.parse(CborTestEncoder.encodeMap(obj));
    assertThatThrownBy(
            () -> AttestationVerifiers.forFormat("packed").verify(mismatched, clientDataHash))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  private static byte[] noneAttestationObject() {
    return attestationObject("none", new LinkedHashMap<>());
  }

  private static byte[] attestationObject(String fmt, Map<Object, Object> attStmt) {
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(new byte[32]);
    authData.write(0x41); // UP | AT
    authData.writeBytes(new byte[] {0, 0, 0, 0});
    authData.writeBytes(new byte[16]); // aaguid
    authData.writeBytes(new byte[] {0, 2}); // credIdLen
    authData.writeBytes(new byte[] {1, 2}); // credId
    authData.writeBytes(sampleCoseKey());

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", fmt);
    obj.put("attStmt", attStmt);
    obj.put("authData", authData.toByteArray());
    return CborTestEncoder.encodeMap(obj);
  }

  /**
   * Builds a packed self-attestation attestationObject. The authData embeds the credential's COSE
   * public key, and attStmt.sig is a real ES256 signature over authData || clientDataHash by the
   * matching private key — a self-consistent fixture.
   */
  private static byte[] packedSelfAttestationObject(byte[] clientDataHash, boolean validSig)
      throws Exception {
    java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("EC");
    gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.KeyPair pair = gen.generateKeyPair();
    java.security.interfaces.ECPublicKey pub =
        (java.security.interfaces.ECPublicKey) pair.getPublic();

    Map<Object, Object> coseMap = new LinkedHashMap<>();
    coseMap.put(1L, 2L);
    coseMap.put(3L, -7L);
    coseMap.put(-1L, 1L);
    coseMap.put(-2L, coordinate(pub.getW().getAffineX()));
    coseMap.put(-3L, coordinate(pub.getW().getAffineY()));
    byte[] cose = CborTestEncoder.encodeMap(coseMap);

    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(new byte[32]); // rpIdHash
    authData.write(0x41); // UP | AT
    authData.writeBytes(new byte[] {0, 0, 0, 0}); // signCount
    authData.writeBytes(new byte[16]); // aaguid
    authData.writeBytes(new byte[] {0, 2}); // credIdLen
    authData.writeBytes(new byte[] {1, 2}); // credId
    authData.writeBytes(cose);
    byte[] authDataBytes = authData.toByteArray();

    ByteArrayOutputStream signed = new ByteArrayOutputStream();
    signed.writeBytes(authDataBytes);
    signed.writeBytes(clientDataHash);
    java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
    signer.initSign(pair.getPrivate());
    signer.update(
        validSig
            ? signed.toByteArray()
            : "garbage".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] sig = signer.sign();

    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("alg", -7L);
    attStmt.put("sig", sig);

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "packed");
    obj.put("attStmt", attStmt);
    obj.put("authData", authDataBytes);
    return CborTestEncoder.encodeMap(obj);
  }

  private static byte[] sampleCoseKey() {
    // A real, on-curve ES256 COSE_Key — CoseKey.parse() validates the point lies on P-256.
    try {
      java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("EC");
      gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
      java.security.interfaces.ECPublicKey pub =
          (java.security.interfaces.ECPublicKey) gen.generateKeyPair().getPublic();
      Map<Object, Object> m = new LinkedHashMap<>();
      m.put(1L, 2L);
      m.put(3L, -7L);
      m.put(-1L, 1L);
      m.put(-2L, coordinate(pub.getW().getAffineX()));
      m.put(-3L, coordinate(pub.getW().getAffineY()));
      return CborTestEncoder.encodeMap(m);
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] coordinate(java.math.BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    if (raw.length > 32) {
      System.arraycopy(raw, raw.length - 32, out, 0, 32);
    } else {
      System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
    }
    return out;
  }

  /**
   * Generates a self-signed X.509 certificate for the given key pair using the {@code
   * sun.security.x509} internal API (accessible in tests via {@code --add-exports}). Not for
   * production use — only to build attestation fixtures in unit tests.
   */
  @SuppressWarnings("restriction")
  private static X509Certificate selfSignedCert(KeyPair keyPair, String dn) throws Exception {
    X509CertInfo info = new X509CertInfo();
    Date from = new Date();
    Date to = new Date(from.getTime() + 365L * 24 * 60 * 60 * 1000);
    info.set(X509CertInfo.VALIDITY, new CertificateValidity(from, to));
    info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger("12345")));
    info.set(X509CertInfo.SUBJECT, new X500Name(dn));
    info.set(X509CertInfo.ISSUER, new X500Name(dn));
    info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
    info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
    AlgorithmId algo = AlgorithmId.get("SHA256withECDSA");
    info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

    X509CertImpl cert = new X509CertImpl(info);
    cert.sign(keyPair.getPrivate(), "SHA256withECDSA");
    return cert;
  }
}
