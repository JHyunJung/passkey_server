package com.crosscert.passkey.unit.fido2.attestation;

import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Self-consistent TPM 2.0 attestation fixture for unit tests. Provides RSA-2048 and ECC P-256
 * variants; mutations allow negative test cases.
 *
 * <p>The fixture builds a complete {@code tpm} attestation object whose:
 *
 * <ul>
 *   <li>pubArea (TPMT_PUBLIC) encodes the credential public key
 *   <li>certInfo (TPMS_ATTEST) carries the correct extraData and attested.name
 *   <li>sig is over certInfo with the AIK key
 *   <li>x5c[0] is a self-signed AIK certificate with EKU and TPM SAN
 * </ul>
 */
final class TpmFixture {

  private static final String TPM_AIK_EKU_OID = "2.23.133.8.3";
  // 2.23.133.2.1 = tcg-at-tpmManufacturer (embedded in SAN OtherName)
  private static final String TPM_MANUFACTURER_OID = "2.23.133.2.1";

  final byte[] clientDataJsonBytes;
  private final KeyPair aikKeyPair;
  private final X509Certificate aikCert;
  private final byte[] attObjBytes;

  private TpmFixture(
      byte[] clientDataJsonBytes, KeyPair aikKeyPair, X509Certificate aikCert, byte[] attObjBytes) {
    this.clientDataJsonBytes = clientDataJsonBytes;
    this.aikKeyPair = aikKeyPair;
    this.aikCert = aikCert;
    this.attObjBytes = attObjBytes;
  }

  /** The raw clientDataJSON bytes (the SHA-256 of these is the clientDataHash). */
  byte[] clientDataJson() {
    return clientDataJsonBytes;
  }

  /** The CBOR-encoded attestation object. */
  byte[] attestationObject() {
    return attObjBytes;
  }

  /** The AIK certificate (leaf). */
  X509Certificate aikCert() {
    return aikCert;
  }

  // ── Mutations (returns new fixture with one field altered)
  // ──────────────────────────────────────

  /** Return a fixture that has a different ver string in attStmt. */
  TpmFixture withVer(String ver) throws Exception {
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("ver", ver);
    return rebuildAttObj(attStmt);
  }

  /**
   * Return a fixture where pubArea encodes a freshly generated (different) key — credential key
   * mismatch.
   */
  TpmFixture withMismatchedPubArea() throws Exception {
    // Generate a new RSA pair; build pubArea from it (does not match credential key in authData).
    KeyPair mismatchedPair = rsaKeyPair();
    RSAPublicKey mismatchedRsa = (RSAPublicKey) mismatchedPair.getPublic();
    byte[] mismatchedPubArea = buildRsaPubArea(mismatchedRsa);
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("pubArea", mismatchedPubArea);
    // Rebuild certInfo/sig consistently with the mismatched pubArea so signature still verifies,
    // but pubArea ↔ cred key mismatch triggers ATTESTATION_INVALID.
    byte[] authDataBytes = (byte[]) parseAttObj().get("authData");
    byte[] clientDataHash = sha256(clientDataJsonBytes);
    byte[] certInfo = buildCertInfo(authDataBytes, clientDataHash, mismatchedPubArea);
    byte[] sig = signRsa(certInfo, aikKeyPair);
    attStmt.put("certInfo", certInfo);
    attStmt.put("sig", sig);
    return rebuildAttObj(attStmt);
  }

  /** Return a fixture with certInfo.extraData set to wrong bytes. */
  TpmFixture withTamperedExtraData() throws Exception {
    Map<Object, Object> attStmt = parseAttStmt();
    byte[] pubArea = (byte[]) attStmt.get("pubArea");
    byte[] authDataBytes = (byte[]) parseAttObj().get("authData");
    // Use all-zero bytes as wrong clientDataHash.
    byte[] wrongClientDataHash = new byte[32];
    byte[] tampered = buildCertInfo(authDataBytes, wrongClientDataHash, pubArea);
    byte[] sig = signRsa(tampered, aikKeyPair);
    attStmt.put("certInfo", tampered);
    attStmt.put("sig", sig);
    return rebuildAttObj(attStmt);
  }

  /**
   * Return a fixture where certInfo.attested.name holds a wrong hash (pointing to a dummy pubArea
   * hash rather than the real one).
   */
  TpmFixture withTamperedAttestedName() throws Exception {
    Map<Object, Object> attStmt = parseAttStmt();
    byte[] pubArea = (byte[]) attStmt.get("pubArea");
    byte[] authDataBytes = (byte[]) parseAttObj().get("authData");
    byte[] clientDataHash = sha256(clientDataJsonBytes);
    // Build certInfo with a tampered name (hash of zeros rather than hash of pubArea).
    byte[] fakeAttestedName = buildAttestedName(new byte[32]);
    byte[] tampered = buildCertInfoWithName(authDataBytes, clientDataHash, fakeAttestedName);
    byte[] sig = signRsa(tampered, aikKeyPair);
    attStmt.put("certInfo", tampered);
    attStmt.put("sig", sig);
    return rebuildAttObj(attStmt);
  }

  /** Return a fixture with a custom x5c chain. */
  TpmFixture withX5c(List<byte[]> chain) throws Exception {
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("x5c", new ArrayList<>(chain));
    return rebuildAttObj(attStmt);
  }

  /** Return a fixture with an AIK cert that lacks the TPM AIK EKU. */
  TpmFixture withoutAikEku() throws Exception {
    X509Certificate certWithoutEku = buildAikCert(aikKeyPair, aikKeyPair, false, true);
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("x5c", List.<Object>of(certWithoutEku.getEncoded()));
    return rebuildAttObj(attStmt);
  }

  /** Return a fixture with an AIK cert that lacks the TPM SAN. */
  TpmFixture withoutTpmSan() throws Exception {
    X509Certificate certWithoutSan = buildAikCert(aikKeyPair, aikKeyPair, true, false);
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("x5c", List.<Object>of(certWithoutSan.getEncoded()));
    return rebuildAttObj(attStmt);
  }

  /** Return a fixture with a CA=true AIK cert (exercises the CA=false enforcement). */
  TpmFixture withCaTrueAikCert() throws Exception {
    X509Certificate caTrueCert = buildAikCertWithBasicConstraints(aikKeyPair, aikKeyPair, true);
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("x5c", List.<Object>of(caTrueCert.getEncoded()));
    return rebuildAttObj(attStmt);
  }

  /** Return a fixture with an X.509 v1 AIK cert (exercises the version=3 enforcement). */
  TpmFixture withV1AikCert() throws Exception {
    X509Certificate v1Cert = buildV1AikCert(aikKeyPair, aikKeyPair);
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("x5c", List.<Object>of(v1Cert.getEncoded()));
    return rebuildAttObj(attStmt);
  }

  /**
   * Return a fixture with a FIDO AAGUID extension in the AIK cert that does NOT match the
   * credential's AAGUID (which is all-zeros in the fixture).
   */
  TpmFixture withMismatchedAikAaguidExtension() throws Exception {
    // Credential AAGUID in the fixture is all-zeros. Use {0x01, 0x00, ...} to mismatch.
    byte[] mismatchedAaguid = new byte[16];
    mismatchedAaguid[0] = 0x01;
    X509Certificate certWithAaguid =
        buildAikCertWithAaguidExtension(aikKeyPair, aikKeyPair, mismatchedAaguid);
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("x5c", List.<Object>of(certWithAaguid.getEncoded()));
    return rebuildAttObj(attStmt);
  }

  /**
   * Return a fixture with the attStmt {@code alg} field overridden to {@code coseAlg}. The sig and
   * certInfo are left unchanged so this triggers the unsupported-algorithm path before any
   * signature check.
   */
  TpmFixture withAlg(long coseAlg) throws Exception {
    Map<Object, Object> attStmt = parseAttStmt();
    attStmt.put("alg", coseAlg);
    return rebuildAttObj(attStmt);
  }

  /**
   * Return a fixture where the last byte of {@code sig} is XOR-flipped. This makes the signature
   * syntactically valid (correct length) but cryptographically invalid, triggering
   * SIGNATURE_INVALID.
   */
  TpmFixture withTamperedSignature() throws Exception {
    Map<Object, Object> attStmt = parseAttStmt();
    byte[] sig = (byte[]) attStmt.get("sig");
    byte[] tampered = sig.clone();
    tampered[tampered.length - 1] ^= (byte) 0xff;
    attStmt.put("sig", tampered);
    return rebuildAttObj(attStmt);
  }

  // ── Static factories
  // ────────────────────────────────────────────────────────────────────────────

  /**
   * Valid TPM 2.0 RSA-2048 attestation with a self-signed AIK cert. clientDataJSON is a synthetic
   * JSON-ish payload unique to this fixture.
   */
  static TpmFixture validRsa(String rpId) throws Exception {
    KeyPair credentialPair = rsaKeyPair();
    KeyPair aikPair = rsaKeyPair();
    X509Certificate aikCert = buildAikCert(aikPair, aikPair, true, true);
    return build(rpId, credentialPair, aikPair, aikCert, "SHA256withRSA", -257L);
  }

  /** Valid TPM 2.0 ECC P-256 attestation. */
  static TpmFixture validEcc(String rpId) throws Exception {
    KeyPair credentialPair = eccKeyPair();
    KeyPair aikPair = rsaKeyPair();
    X509Certificate aikCert = buildAikCert(aikPair, aikPair, true, true);
    return build(rpId, credentialPair, aikPair, aikCert, "SHA256withRSA", -257L);
  }

  /**
   * Valid RSA attestation where the AIK cert is issued by {@code caKey}/{@code caCert}. The x5c
   * chain includes both the AIK cert and the CA cert so PKIX validation can build the path.
   */
  static TpmFixture withCa(KeyPair caKey, X509Certificate caCert, String rpId) throws Exception {
    KeyPair credentialPair = rsaKeyPair();
    KeyPair aikPair = rsaKeyPair();
    String caDn = caCert.getSubjectX500Principal().getName();
    // Use the CA's RFC-2253 DN as the issuer in the AIK cert.
    // BouncyCastle accepts LDAP-style DN; X500Name from RFC-2253 might need reversal.
    // Simpler: use a fixed issuer DN that matches the CA cert built with selfSignedCa.
    X509Certificate aikCert = buildAikCert(aikPair, caKey, "CN=TPM Test CA", true, true);
    TpmFixture base = build(rpId, credentialPair, aikPair, aikCert, "SHA256withRSA", -257L);
    // Patch x5c to include [aikCert, caCert] so PKIX can build the full chain.
    return base.withX5c(List.of(aikCert.getEncoded(), caCert.getEncoded()));
  }

  /** Generate an RSA 2048-bit key pair. */
  static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    return gen.generateKeyPair();
  }

  /** Build a self-signed CA certificate (CA=true) for use as a trust anchor. */
  static X509Certificate selfSignedCa(String dn, KeyPair pair) throws Exception {
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
            builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
  }

  // ── Internal builders ──────────────────────────────────────────────────────────────────────────

  private static TpmFixture build(
      String rpId,
      KeyPair credentialPair,
      KeyPair aikPair,
      X509Certificate aikCert,
      String aikSigAlg,
      long coseAlg)
      throws Exception {

    // clientDataJSON is a synthetic string (hash is what matters)
    byte[] clientDataJson =
        ("{\"type\":\"webauthn.create\",\"challenge\":\"test\",\"origin\":\"https://"
                + rpId
                + "\"}")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);

    byte[] clientDataHash = sha256(clientDataJson);

    // Build pubArea
    byte[] pubArea = buildPubArea(credentialPair);

    // Build authData (rpIdHash 32 + flags 1 + signCount 4 + aaguid 16 + credIdLen 2 + credId 4 +
    // coseKey)
    byte[] aaguid = new byte[16]; // all-zero AAGUID
    byte[] credId = new byte[] {1, 2, 3, 4};
    byte[] coseKey = buildCoseKey(credentialPair);
    ByteArrayOutputStream authDataOut = new ByteArrayOutputStream();
    authDataOut.write(new byte[32]); // rpIdHash (zeros for fixture)
    authDataOut.write(0x45); // UP | UV | AT
    authDataOut.writeBytes(new byte[] {0, 0, 0, 0}); // signCount
    authDataOut.writeBytes(aaguid);
    authDataOut.writeBytes(new byte[] {0, (byte) credId.length});
    authDataOut.writeBytes(credId);
    authDataOut.writeBytes(coseKey);
    byte[] authDataBytes = authDataOut.toByteArray();

    // Build certInfo
    byte[] certInfo = buildCertInfo(authDataBytes, clientDataHash, pubArea);

    // Sign certInfo with AIK private key
    byte[] sig;
    if (aikSigAlg.contains("RSA")) {
      sig = signRsa(certInfo, aikPair);
    } else {
      sig = signEcdsa(certInfo, aikPair);
    }

    // Build attStmt
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("ver", "2.0");
    attStmt.put("alg", coseAlg);
    attStmt.put("x5c", List.<Object>of(aikCert.getEncoded()));
    attStmt.put("sig", sig);
    attStmt.put("certInfo", certInfo);
    attStmt.put("pubArea", pubArea);

    // Build attestation object
    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "tpm");
    obj.put("attStmt", attStmt);
    obj.put("authData", authDataBytes);
    byte[] attObj = CborTestEncoder.encodeMap(obj);

    return new TpmFixture(clientDataJson, aikPair, aikCert, attObj);
  }

  // ── TPMT_PUBLIC builders ───────────────────────────────────────────────────────────────────────

  private static byte[] buildPubArea(KeyPair pair) {
    if (pair.getPublic() instanceof RSAPublicKey rsa) {
      return buildRsaPubArea(rsa);
    } else if (pair.getPublic() instanceof ECPublicKey ec) {
      return buildEccPubArea(ec);
    } else {
      throw new IllegalArgumentException("Unsupported key type: " + pair.getPublic().getClass());
    }
  }

  static byte[] buildRsaPubArea(RSAPublicKey rsa) {
    byte[] modulus = toUnsignedBytes(rsa.getModulus(), 256); // 2048-bit = 256 bytes
    ByteBuffer buf = ByteBuffer.allocate(2 + 2 + 4 + 2 + 2 + 2 + 2 + 4 + 2 + modulus.length);
    buf.putShort((short) 0x0001); // TPM_ALG_RSA
    buf.putShort((short) 0x000B); // nameAlg = TPM_ALG_SHA256
    buf.putInt(0x00050072); // objectAttributes
    buf.putShort((short) 0); // authPolicy empty
    buf.putShort((short) 0x0010); // symmetric NULL
    buf.putShort((short) 0x0010); // scheme NULL
    buf.putShort((short) 2048); // keyBits
    buf.putInt(0x00010001); // exponent 65537
    buf.putShort((short) modulus.length);
    buf.put(modulus);
    return buf.array();
  }

  private static byte[] buildEccPubArea(ECPublicKey ec) {
    byte[] x = toUnsignedBytes(ec.getW().getAffineX(), 32);
    byte[] y = toUnsignedBytes(ec.getW().getAffineY(), 32);
    ByteBuffer buf =
        ByteBuffer.allocate(2 + 2 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + x.length + 2 + y.length);
    buf.putShort((short) 0x0023); // TPM_ALG_ECC
    buf.putShort((short) 0x000B); // nameAlg = TPM_ALG_SHA256
    buf.putInt(0x00050072); // objectAttributes
    buf.putShort((short) 0); // authPolicy empty
    buf.putShort((short) 0x0010); // symmetric NULL
    buf.putShort((short) 0x0010); // scheme NULL
    buf.putShort((short) 0x0003); // curveId P-256
    buf.putShort((short) 0x0010); // kdf NULL
    buf.putShort((short) x.length);
    buf.put(x);
    buf.putShort((short) y.length);
    buf.put(y);
    return buf.array();
  }

  // ── TPMS_ATTEST builders ───────────────────────────────────────────────────────────────────────

  static byte[] buildCertInfo(byte[] authDataBytes, byte[] clientDataHash, byte[] pubArea)
      throws Exception {
    byte[] extraData = sha256(concat(authDataBytes, clientDataHash));
    byte[] attestedName = buildAttestedName(sha256(pubArea));
    return buildCertInfoWithName(authDataBytes, clientDataHash, attestedName);
  }

  private static byte[] buildCertInfoWithName(
      byte[] authDataBytes, byte[] clientDataHash, byte[] attestedName) throws Exception {
    byte[] extraData = sha256(concat(authDataBytes, clientDataHash));
    // magic(4) + type(2) + qualifiedSigner len(2)=0 + extraData len(2)+extraData
    //   + clockInfo(17) + firmwareVersion(8) + name len(2)+name + qualifiedName len(2)=0
    ByteBuffer buf =
        ByteBuffer.allocate(
            4 + 2 + 2 + 2 + extraData.length + 17 + 8 + 2 + attestedName.length + 2);
    buf.putInt(0xFF544347); // TPM_GENERATED_VALUE
    buf.putShort((short) 0x8017); // TPM_ST_ATTEST_CERTIFY
    buf.putShort((short) 0); // qualifiedSigner empty
    buf.putShort((short) extraData.length);
    buf.put(extraData);
    buf.put(new byte[17]); // clockInfo
    buf.putLong(0L); // firmwareVersion
    buf.putShort((short) attestedName.length);
    buf.put(attestedName);
    buf.putShort((short) 0); // qualifiedName empty
    return buf.array();
  }

  /** Build attested name = nameAlg (2B BE, 0x000B = SHA-256) || pubAreaHash (32 bytes). */
  static byte[] buildAttestedName(byte[] pubAreaHash) {
    ByteBuffer name = ByteBuffer.allocate(2 + pubAreaHash.length);
    name.putShort((short) 0x000B); // TPM_ALG_SHA256
    name.put(pubAreaHash);
    return name.array();
  }

  // ── Signature helpers ──────────────────────────────────────────────────────────────────────────

  static byte[] signRsa(byte[] data, KeyPair pair) throws Exception {
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initSign(pair.getPrivate());
    sig.update(data);
    return sig.sign();
  }

  static byte[] signEcdsa(byte[] data, KeyPair pair) throws Exception {
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(pair.getPrivate());
    sig.update(data);
    return sig.sign();
  }

  // ── COSE key builders ──────────────────────────────────────────────────────────────────────────

  private static byte[] buildCoseKey(KeyPair pair) {
    if (pair.getPublic() instanceof RSAPublicKey rsa) {
      return buildRsaCoseKey(rsa);
    } else if (pair.getPublic() instanceof ECPublicKey ec) {
      return buildEccCoseKey(ec);
    } else {
      throw new IllegalArgumentException("Unsupported key: " + pair.getPublic().getClass());
    }
  }

  private static byte[] buildRsaCoseKey(RSAPublicKey rsa) {
    byte[] n = toUnsignedBytes(rsa.getModulus(), 256);
    byte[] e = rsa.getPublicExponent().toByteArray();
    // strip leading zero if present
    if (e.length > 3 && e[0] == 0) {
      byte[] trimmed = new byte[e.length - 1];
      System.arraycopy(e, 1, trimmed, 0, trimmed.length);
      e = trimmed;
    }
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 3L); // kty = RSA
    m.put(3L, -257L); // alg = RS256
    m.put(-1L, n); // n
    m.put(-2L, e); // e
    return CborTestEncoder.encodeMap(m);
  }

  private static byte[] buildEccCoseKey(ECPublicKey ec) {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L); // kty = EC2
    m.put(3L, -7L); // alg = ES256
    m.put(-1L, 1L); // crv = P-256
    m.put(-2L, toUnsignedBytes(ec.getW().getAffineX(), 32)); // x
    m.put(-3L, toUnsignedBytes(ec.getW().getAffineY(), 32)); // y
    return CborTestEncoder.encodeMap(m);
  }

  // ── Certificate builder ────────────────────────────────────────────────────────────────────────

  /**
   * Build an AIK certificate. The cert is issued (signed) by {@code issuerPair}. When {@code
   * includeEku} is true the AIK EKU (2.23.133.8.3) is added; when {@code includeSan} is true the
   * TPM SAN OtherName (2.23.133.2.1 = manufacturer) is added.
   *
   * <p>The issuer DN defaults to the subject DN (self-signed). Use the overload with {@code
   * issuerDn} to build a cert issued by a CA with a different DN.
   */
  static X509Certificate buildAikCert(
      KeyPair subjectPair, KeyPair issuerPair, boolean includeEku, boolean includeSan)
      throws Exception {
    return buildAikCert(subjectPair, issuerPair, "CN=TPM AIK Test", includeEku, includeSan);
  }

  static X509Certificate buildAikCert(
      KeyPair subjectPair,
      KeyPair issuerPair,
      String issuerDn,
      boolean includeEku,
      boolean includeSan)
      throws Exception {
    Instant now = Instant.now();
    X500Name subject = new X500Name("CN=TPM AIK Test");
    X500Name issuer = new X500Name(issuerDn);
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            subject,
            subjectPair.getPublic());

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

    if (includeEku) {
      builder.addExtension(
          Extension.extendedKeyUsage,
          false,
          new ExtendedKeyUsage(
              new KeyPurposeId[] {
                KeyPurposeId.getInstance(
                    new org.bouncycastle.asn1.ASN1ObjectIdentifier(TPM_AIK_EKU_OID))
              }));
    }

    if (includeSan) {
      // OtherName: OID 2.23.133.2.1, value UTF8String "id:4e544300" (manufacturer id)
      org.bouncycastle.asn1.ASN1ObjectIdentifier sanOid =
          new org.bouncycastle.asn1.ASN1ObjectIdentifier(TPM_MANUFACTURER_OID);
      org.bouncycastle.asn1.DERUTF8String mfrValue =
          new org.bouncycastle.asn1.DERUTF8String("id:4e544300");
      OtherName otherName = new OtherName(sanOid, mfrValue);
      GeneralNames san = new GeneralNames(new GeneralName(GeneralName.otherName, otherName));
      builder.addExtension(Extension.subjectAlternativeName, false, san);
    }

    String sigAlg =
        subjectPair.getPublic().getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
    String issuerSigAlg =
        issuerPair.getPublic().getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";

    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder(issuerSigAlg).build(issuerPair.getPrivate())));
  }

  /**
   * Build an AIK cert with BasicConstraints CA set to {@code caValue} (true → CA cert, false →
   * leaf). All other fields (EKU, SAN) are present and valid so that only the CA flag triggers
   * rejection.
   */
  private static X509Certificate buildAikCertWithBasicConstraints(
      KeyPair subjectPair, KeyPair issuerPair, boolean caValue) throws Exception {
    Instant now = Instant.now();
    X500Name subject = new X500Name("CN=TPM AIK Test");
    X500Name issuer = new X500Name("CN=TPM AIK Test");
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            subject,
            subjectPair.getPublic());

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(caValue));
    builder.addExtension(
        Extension.extendedKeyUsage,
        false,
        new ExtendedKeyUsage(
            new KeyPurposeId[] {
              KeyPurposeId.getInstance(new ASN1ObjectIdentifier(TPM_AIK_EKU_OID))
            }));
    ASN1ObjectIdentifier sanOid = new ASN1ObjectIdentifier(TPM_MANUFACTURER_OID);
    org.bouncycastle.asn1.DERUTF8String mfrValue =
        new org.bouncycastle.asn1.DERUTF8String("id:4e544300");
    OtherName otherName = new OtherName(sanOid, mfrValue);
    GeneralNames san = new GeneralNames(new GeneralName(GeneralName.otherName, otherName));
    builder.addExtension(Extension.subjectAlternativeName, false, san);

    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerPair.getPrivate())));
  }

  /**
   * Build an X.509 v1 AIK certificate. JcaX509v1CertificateBuilder produces v1 certs that have no
   * extension support, so the version check fires before EKU / SAN checks.
   */
  private static X509Certificate buildV1AikCert(KeyPair subjectPair, KeyPair issuerPair)
      throws Exception {
    Instant now = Instant.now();
    X500Name subject = new X500Name("CN=TPM AIK Test");
    X500Name issuer = new X500Name("CN=TPM AIK Test");
    JcaX509v1CertificateBuilder builder =
        new JcaX509v1CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            subject,
            subjectPair.getPublic());
    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerPair.getPrivate())));
  }

  /**
   * Build an AIK cert that includes the FIDO AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4) with
   * the given {@code aaguidBytes}. The extension value is an OCTET STRING wrapping the 16-byte
   * AAGUID — matching the two-level unwrap in {@code TpmAttestationVerifier.fidoAaguidExtension}.
   */
  private static X509Certificate buildAikCertWithAaguidExtension(
      KeyPair subjectPair, KeyPair issuerPair, byte[] aaguidBytes) throws Exception {
    Instant now = Instant.now();
    X500Name subject = new X500Name("CN=TPM AIK Test");
    X500Name issuer = new X500Name("CN=TPM AIK Test");
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            subject,
            subjectPair.getPublic());

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(
        Extension.extendedKeyUsage,
        false,
        new ExtendedKeyUsage(
            new KeyPurposeId[] {
              KeyPurposeId.getInstance(new ASN1ObjectIdentifier(TPM_AIK_EKU_OID))
            }));
    ASN1ObjectIdentifier sanOid = new ASN1ObjectIdentifier(TPM_MANUFACTURER_OID);
    org.bouncycastle.asn1.DERUTF8String mfrValue =
        new org.bouncycastle.asn1.DERUTF8String("id:4e544300");
    OtherName otherName = new OtherName(sanOid, mfrValue);
    GeneralNames san = new GeneralNames(new GeneralName(GeneralName.otherName, otherName));
    builder.addExtension(Extension.subjectAlternativeName, false, san);

    // FIDO AAGUID extension: extension value is an OCTET STRING containing the 16-byte AAGUID.
    // BouncyCastle addExtension wraps the provided bytes in the outer OCTET STRING that
    // getExtensionValue() returns; the inner OCTET STRING is what we encode here.
    ASN1ObjectIdentifier fidoAaguidOid = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
    DEROctetString innerOctetString = new DEROctetString(aaguidBytes);
    builder.addExtension(fidoAaguidOid, false, innerOctetString);

    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerPair.getPrivate())));
  }

  // ── CBOR parse helpers for mutation builders ───────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private Map<Object, Object> parseAttObj() throws Exception {
    // We just rebuild from the stored bytes by re-parsing the CBOR.
    // Since we build attObjBytes ourselves from a LinkedHashMap, we can reverse-engineer
    // the contents from the stored state fields. But simpler: keep original fields as mutable map.
    // For the mutation builders we work by directly manipulating the attStmt map stored in
    // a copy of the attObj. Here we use AttestationObject to extract the pieces we need.
    com.crosscert.passkey.fido2.model.AttestationObject parsed =
        com.crosscert.passkey.fido2.model.AttestationObject.parse(attObjBytes);
    // Reconstruct the outer map with fmt + attStmt + authData
    Map<Object, Object> outer = new LinkedHashMap<>();
    outer.put("fmt", parsed.format());
    outer.put("attStmt", new LinkedHashMap<>(parsed.attestationStatement()));
    outer.put("authData", parsed.authenticatorData().rawBytes());
    return outer;
  }

  @SuppressWarnings("unchecked")
  private Map<Object, Object> parseAttStmt() throws Exception {
    Map<Object, Object> outer = parseAttObj();
    return (Map<Object, Object>) outer.get("attStmt");
  }

  private TpmFixture rebuildAttObj(Map<Object, Object> newAttStmt) throws Exception {
    Map<Object, Object> outer = parseAttObj();
    outer.put("attStmt", newAttStmt);
    byte[] newAttObjBytes = CborTestEncoder.encodeMap(outer);
    return new TpmFixture(clientDataJsonBytes, aikKeyPair, aikCert, newAttObjBytes);
  }

  // ── Utilities ──────────────────────────────────────────────────────────────────────────────────

  static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] result = new byte[a.length + b.length];
    System.arraycopy(a, 0, result, 0, a.length);
    System.arraycopy(b, 0, result, a.length, b.length);
    return result;
  }

  /**
   * Convert a {@link BigInteger} to a big-endian unsigned byte array of exactly {@code length}
   * bytes (zero-padded from the left, or trimmed if the value's magnitude requires fewer bytes).
   */
  private static byte[] toUnsignedBytes(BigInteger value, int length) {
    byte[] raw = value.toByteArray();
    byte[] out = new byte[length];
    if (raw.length > length) {
      // Strip leading sign byte(s)
      System.arraycopy(raw, raw.length - length, out, 0, length);
    } else {
      System.arraycopy(raw, 0, out, length - raw.length, raw.length);
    }
    return out;
  }

  /** Generate a fresh ECC P-256 key pair. */
  private static KeyPair eccKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    return gen.generateKeyPair();
  }
}
