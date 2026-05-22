package com.crosscert.passkey.unit.fido2.mds;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test-only builder for FIDO MDS3 metadata BLOB fixtures. Produces a self-signed root CA, a BLOB
 * signing certificate chained to it, and a signed JWS BLOB — so the {@code fido2.mds} parser can be
 * exercised without reaching the real FIDO Alliance endpoint.
 */
public final class MdsTestFixtures {

  private MdsTestFixtures() {}

  /** A root CA keypair + certificate, plus a leaf signing keypair + certificate chained to it. */
  public record Pki(X509Certificate rootCa, X509Certificate signingCert, PrivateKey signingKey) {}

  /** Build a 2-cert PKI: self-signed root CA + a leaf signing cert issued by it. */
  public static Pki buildPki() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair rootPair = gen.generateKeyPair();
    KeyPair leafPair = gen.generateKeyPair();

    X509Certificate rootCa = selfSigned(rootPair, "CN=Test FIDO MDS Root", true);
    X509Certificate signingCert =
        issued(leafPair, "CN=Test MDS BLOB Signer", rootPair, "CN=Test FIDO MDS Root", false);
    return new Pki(rootCa, signingCert, leafPair.getPrivate());
  }

  /**
   * Sign {@code payloadJson} as an RS256 JWS with the {@code x5c} header carrying [signingCert,
   * rootCa] — the form a real FIDO MDS3 BLOB uses.
   */
  public static String signBlob(String payloadJson, Pki pki) throws Exception {
    JWSSigner signer = new RSASSASigner(pki.signingKey());
    JWSHeader header =
        new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(JOSEObjectType.JWT)
            .x509CertChain(
                List.of(
                    Base64.encode(pki.signingCert().getEncoded()),
                    Base64.encode(pki.rootCa().getEncoded())))
            .build();
    com.nimbusds.jose.Payload payload = new com.nimbusds.jose.Payload(payloadJson);
    com.nimbusds.jose.JWSObject jws = new com.nimbusds.jose.JWSObject(header, payload);
    jws.sign(signer);
    return jws.serialize();
  }

  private static X509Certificate selfSigned(KeyPair pair, String dn, boolean ca) throws Exception {
    return issued(pair, dn, pair, dn, ca);
  }

  private static X509Certificate issued(
      KeyPair subjectPair, String subjectDn, KeyPair issuerPair, String issuerDn, boolean ca)
      throws Exception {
    Instant now = Instant.now();
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn),
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            new X500Name(subjectDn),
            subjectPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(issuerPair.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }
}
