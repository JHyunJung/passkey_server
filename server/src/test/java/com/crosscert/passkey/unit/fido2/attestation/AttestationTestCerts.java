package com.crosscert.passkey.unit.fido2.attestation;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Shared BouncyCastle certificate builders for attestation verifier tests.
 *
 * <p>Extracts the repeated {@code selfSignedCa} pattern that appears in Apple, AndroidKey, U2F,
 * SafetyNet, and TPM verifier tests. The signing algorithm is chosen from the key type: EC keys use
 * {@code SHA256withECDSA}; RSA keys use {@code SHA256withRSA}.
 */
final class AttestationTestCerts {

  private AttestationTestCerts() {}

  /**
   * Build a self-signed CA certificate (Basic Constraints CA=true).
   *
   * <p>Signing algorithm is selected automatically from the key algorithm: {@code EC} → {@code
   * SHA256withECDSA}, {@code RSA} → {@code SHA256withRSA}.
   *
   * @param pair key pair whose public key is embedded and whose private key signs the cert
   * @param dn X.500 distinguished name (e.g. {@code "CN=Test CA"})
   * @return a self-signed CA certificate valid for 366 days from yesterday
   */
  static X509Certificate selfSignedCa(KeyPair pair, String dn) throws Exception {
    String alg = "EC".equals(pair.getPublic().getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
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
        .getCertificate(builder.build(new JcaContentSignerBuilder(alg).build(pair.getPrivate())));
  }
}
