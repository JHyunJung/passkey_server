package com.crosscert.passkey.integration.credential;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * In-memory fixture builder for FIDO MDS3 integration tests. Generates per-AAGUID root CA
 * certificates and attestation leaf certificates so {@code RegistrationStrictIntegrationTest} can
 * build self-consistent attestationObjects that the strict registration path validates against the
 * constructed {@link MdsTrustAnchorSource}.
 *
 * <p>Call {@link #build()} once, then obtain per-AAGUID helpers via {@link #scenarioFor(UUID)}. The
 * builder is determinism-neutral — it generates fresh keys on each run.
 */
public final class MdsBlobFixtureBuilder {

  /** The FIDO AAGUID certificate extension OID (WebAuthn L3 §8.2.1). */
  public static final String FIDO_AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4";

  /** §8.2.1-compliant subject DN for attestation leaf certificates. */
  public static final String ATT_OU_DN =
      "CN=Test Attestation, OU=Authenticator Attestation, O=TestOrg, C=US";

  // --- Well-known AAGUIDs used in integration tests ---
  public static final UUID PACKED_AAGUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
  public static final UUID APPLE_AAGUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
  public static final UUID ANDROID_KEY_AAGUID =
      UUID.fromString("33333333-3333-3333-3333-333333333333");
  public static final UUID TPM_AAGUID = UUID.fromString("66666666-6666-6666-6666-666666666666");
  public static final UUID REVOKED_AAGUID = UUID.fromString("77777777-7777-7777-7777-777777777777");

  /**
   * The all-zero AAGUID (§6.1 "no AAGUID" sentinel). Registered in the fixture MDS as
   * FIDO_CERTIFIED so that the MDS trust check passes and the policy layer (allowZeroAaguid=false)
   * is actually reached in Test 6.
   */
  public static final UUID ZERO_AAGUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

  private final Map<UUID, AaguidFixture> fixturesByAaguid = new LinkedHashMap<>();

  private MdsBlobFixtureBuilder() {}

  /**
   * Build a new fixture set covering the standard AAGUIDs. Each AAGUID gets its own root CA +
   * attestation leaf certificate. The REVOKED_AAGUID entry is marked as revoked.
   */
  public static MdsBlobFixtureBuilder build() throws Exception {
    MdsBlobFixtureBuilder b = new MdsBlobFixtureBuilder();
    b.addAaguid(PACKED_AAGUID, StatusReport.FIDO_CERTIFIED);
    b.addAaguid(APPLE_AAGUID, StatusReport.FIDO_CERTIFIED);
    b.addAaguid(ANDROID_KEY_AAGUID, StatusReport.FIDO_CERTIFIED);
    b.addAaguid(TPM_AAGUID, StatusReport.FIDO_CERTIFIED);
    b.addAaguid(REVOKED_AAGUID, StatusReport.REVOKED);
    b.addAaguid(ZERO_AAGUID, StatusReport.FIDO_CERTIFIED);
    return b;
  }

  private void addAaguid(UUID aaguid, StatusReport status) throws Exception {
    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
    ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));

    KeyPair rootPair = ecGen.generateKeyPair();
    String rootDn = "CN=Test Root CA " + aaguid.toString().substring(0, 8) + ", O=Test, C=US";
    X509Certificate rootCa = selfSigned(rootPair, rootDn, true);

    KeyPair leafPair = ecGen.generateKeyPair();
    X509Certificate leafCert = issued(leafPair, ATT_OU_DN, rootPair, rootDn, false, aaguid);

    fixturesByAaguid.put(aaguid, new AaguidFixture(aaguid, rootCa, rootPair, leafCert, leafPair));
  }

  /** Returns an {@link AaguidFixture} for the given AAGUID, or throws if not pre-built. */
  public AaguidFixture scenarioFor(UUID aaguid) {
    AaguidFixture f = fixturesByAaguid.get(aaguid);
    if (f == null) {
      throw new IllegalArgumentException("No fixture registered for AAGUID: " + aaguid);
    }
    return f;
  }

  /**
   * Builds an {@link MdsTrustAnchorSource} from all registered AAGUID entries. This is the object
   * injected into the Spring context so {@code RegistrationService} uses it in strict mode.
   */
  public MdsTrustAnchorSource toTrustAnchorSource() {
    List<MetadataEntry> entries = new ArrayList<>();
    for (AaguidFixture f : fixturesByAaguid.values()) {
      entries.add(new MetadataEntry(f.aaguid(), List.of(f.rootCa()), List.of(f.status())));
    }
    return new MdsTrustAnchorSource(entries);
  }

  // -----------------------------------------------------------------------------------------
  // Certificate helpers.
  // -----------------------------------------------------------------------------------------

  private static X509Certificate selfSigned(KeyPair pair, String dn, boolean ca) throws Exception {
    return issued(pair, dn, pair, dn, ca, null);
  }

  static X509Certificate issued(
      KeyPair subjectPair,
      String subjectDn,
      KeyPair issuerPair,
      String issuerDn,
      boolean ca,
      UUID aaguid)
      throws Exception {
    Instant now = Instant.now();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn),
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            new X500Name(subjectDn),
            subjectPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
    if (aaguid != null) {
      byte[] aaguidBytes = uuidToBytes(aaguid);
      // FIDO AAGUID extension: value is a DER OCTET STRING wrapping the 16 AAGUID bytes.
      builder.addExtension(
          new ASN1ObjectIdentifier(FIDO_AAGUID_OID), false, new DEROctetString(aaguidBytes));
    }
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA").build(issuerPair.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }

  /** Encode a UUID as the big-endian 16-byte form expected in an AAGUID field. */
  public static byte[] uuidToBytes(UUID uuid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  /**
   * Encodes an ES256 COSE_Key from the given EC public key. The encoding follows RFC 8152 §13.1.1:
   * kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x(32 bytes), y(32 bytes).
   */
  public static byte[] ecCoseKey(ECPublicKey pub) {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L);
    m.put(3L, -7L);
    m.put(-1L, 1L);
    m.put(-2L, coordinate(pub.getW().getAffineX()));
    m.put(-3L, coordinate(pub.getW().getAffineY()));
    return cborEncodeMap(m);
  }

  /** Pads or trims a BigInteger coordinate to 32 bytes big-endian. */
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

  // -----------------------------------------------------------------------------------------
  // Minimal CBOR encoder (duplicated from CborTestEncoder to avoid cross-package dependency).
  // -----------------------------------------------------------------------------------------

  static byte[] cborEncodeMap(Map<Object, Object> map) {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    cborWriteTypeLen(out, 5, map.size());
    for (Map.Entry<Object, Object> e : map.entrySet()) {
      cborWriteItem(out, e.getKey());
      cborWriteItem(out, e.getValue());
    }
    return out.toByteArray();
  }

  @SuppressWarnings("unchecked")
  private static void cborWriteItem(java.io.ByteArrayOutputStream out, Object v) {
    if (v instanceof Long l) {
      if (l >= 0) cborWriteTypeLen(out, 0, l);
      else cborWriteTypeLen(out, 1, -1 - l);
    } else if (v instanceof Integer i) {
      cborWriteItem(out, (long) i);
    } else if (v instanceof byte[] b) {
      cborWriteTypeLen(out, 2, b.length);
      out.write(b, 0, b.length);
    } else if (v instanceof String s) {
      byte[] utf8 = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      cborWriteTypeLen(out, 3, utf8.length);
      out.write(utf8, 0, utf8.length);
    } else if (v instanceof List<?> list) {
      cborWriteTypeLen(out, 4, list.size());
      for (Object item : list) cborWriteItem(out, item);
    } else if (v instanceof Map<?, ?> m) {
      cborWriteTypeLen(out, 5, m.size());
      for (Map.Entry<?, ?> e : ((Map<Object, Object>) m).entrySet()) {
        cborWriteItem(out, e.getKey());
        cborWriteItem(out, e.getValue());
      }
    } else {
      throw new IllegalArgumentException("Unsupported CBOR value type: " + v.getClass());
    }
  }

  private static void cborWriteTypeLen(java.io.ByteArrayOutputStream out, int mt, long len) {
    int major = mt << 5;
    if (len < 24) {
      out.write(major | (int) len);
    } else if (len < 256) {
      out.write(major | 24);
      out.write((int) len);
    } else if (len < 65536) {
      out.write(major | 25);
      out.write((int) (len >> 8));
      out.write((int) (len & 0xff));
    } else {
      out.write(major | 26);
      out.write((int) (len >> 24));
      out.write((int) (len >> 16) & 0xff);
      out.write((int) (len >> 8) & 0xff);
      out.write((int) (len & 0xff));
    }
  }

  // -----------------------------------------------------------------------------------------
  // Inner record.
  // -----------------------------------------------------------------------------------------

  /**
   * Per-AAGUID fixture: holds the root CA (trust anchor), the attestation leaf certificate and
   * private key (for signing attestation statements), and the current status report for the
   * authenticator. Provides helper methods to build attestationObject bytes for integration tests.
   */
  public static final class AaguidFixture {

    private final UUID aaguid;
    private final X509Certificate rootCa;
    private final KeyPair rootPair;
    private final X509Certificate leafCert;
    private final KeyPair leafPair;

    AaguidFixture(
        UUID aaguid,
        X509Certificate rootCa,
        KeyPair rootPair,
        X509Certificate leafCert,
        KeyPair leafPair) {
      this.aaguid = aaguid;
      this.rootCa = rootCa;
      this.rootPair = rootPair;
      this.leafCert = leafCert;
      this.leafPair = leafPair;
    }

    public UUID aaguid() {
      return aaguid;
    }

    public X509Certificate rootCa() {
      return rootCa;
    }

    public X509Certificate leafCert() {
      return leafCert;
    }

    public PrivateKey leafKey() {
      return leafPair.getPrivate();
    }

    StatusReport status() {
      // Derive status from the outer map: REVOKED if the AAGUID matches REVOKED_AAGUID.
      return REVOKED_AAGUID.equals(aaguid) ? StatusReport.REVOKED : StatusReport.FIDO_CERTIFIED;
    }

    /**
     * Build a packed full-attestation attestationObject for this AAGUID. The credential key pair is
     * freshly generated (ES256); the attestation is signed by this fixture's leaf key. The rpIdHash
     * field in authData is filled with the SHA-256 of {@code rpId}.
     */
    public byte[] buildPackedFullAttestationObject(byte[] clientDataHash, String rpId)
        throws Exception {
      byte[] rpIdHash = sha256(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      byte[] aaguidBytes = uuidToBytes(aaguid);

      KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
      ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
      KeyPair credPair = ecGen.generateKeyPair();
      byte[] coseKey = ecCoseKey((ECPublicKey) credPair.getPublic());

      byte[] authData = buildAuthData(rpIdHash, aaguidBytes, coseKey);

      // signedData = authData || clientDataHash
      java.io.ByteArrayOutputStream signed = new java.io.ByteArrayOutputStream();
      signed.writeBytes(authData);
      signed.writeBytes(clientDataHash);
      java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
      sig.initSign(leafPair.getPrivate());
      sig.update(signed.toByteArray());
      byte[] signature = sig.sign();

      Map<Object, Object> attStmt = new LinkedHashMap<>();
      attStmt.put("alg", -7L); // ES256
      attStmt.put("sig", signature);
      attStmt.put("x5c", List.of(leafCert.getEncoded()));

      Map<Object, Object> ao = new LinkedHashMap<>();
      ao.put("fmt", "packed");
      ao.put("attStmt", attStmt);
      ao.put("authData", authData);
      return cborEncodeMap(ao);
    }

    /**
     * Build a packed self-attestation attestationObject for this AAGUID. Useful for testing the
     * strict self-attestation path (MDS_TRUST_FAILED when AAGUID not in MDS).
     */
    public byte[] buildPackedSelfAttestationObject(byte[] clientDataHash, String rpId)
        throws Exception {
      byte[] rpIdHash = sha256(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      byte[] aaguidBytes = uuidToBytes(aaguid);

      KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
      ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
      KeyPair credPair = ecGen.generateKeyPair();
      byte[] coseKey = ecCoseKey((ECPublicKey) credPair.getPublic());

      byte[] authData = buildAuthData(rpIdHash, aaguidBytes, coseKey);

      java.io.ByteArrayOutputStream signed = new java.io.ByteArrayOutputStream();
      signed.writeBytes(authData);
      signed.writeBytes(clientDataHash);
      java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
      sig.initSign(credPair.getPrivate());
      sig.update(signed.toByteArray());
      byte[] signature = sig.sign();

      Map<Object, Object> attStmt = new LinkedHashMap<>();
      attStmt.put("alg", -7L);
      attStmt.put("sig", signature);

      Map<Object, Object> ao = new LinkedHashMap<>();
      ao.put("fmt", "packed");
      ao.put("attStmt", attStmt);
      ao.put("authData", authData);
      return cborEncodeMap(ao);
    }

    private static byte[] buildAuthData(byte[] rpIdHash, byte[] aaguidBytes, byte[] coseKey) {
      java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
      out.writeBytes(rpIdHash); // 32 bytes
      out.write(0x45); // UP | UV | AT flags
      out.writeBytes(new byte[] {0, 0, 0, 0}); // signCount = 0
      out.writeBytes(aaguidBytes); // 16-byte AAGUID
      out.writeBytes(new byte[] {0, 4}); // credIdLen = 4
      out.writeBytes(new byte[] {1, 2, 3, 4}); // credId
      out.writeBytes(coseKey);
      return out.toByteArray();
    }

    private static byte[] sha256(byte[] data) throws Exception {
      return java.security.MessageDigest.getInstance("SHA-256").digest(data);
    }
  }
}
