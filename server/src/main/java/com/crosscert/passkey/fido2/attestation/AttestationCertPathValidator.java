package com.crosscert.passkey.fido2.attestation;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * Validates an attestation certificate chain up to a set of trust anchors using the JDK's PKIX
 * {@code CertPathValidator}. Used by strict-mode attestation verifiers to confirm an
 * authenticator's attestation certificate chains to an MDS-sourced root.
 *
 * <p>Revocation checking (CRL / OCSP) is disabled: FIDO MDS metadata freshness — not certificate
 * revocation lists — governs authenticator trust, and attestation certificates are typically
 * long-lived batch certificates without CRL distribution points.
 */
public final class AttestationCertPathValidator {

  private AttestationCertPathValidator() {}

  /**
   * Returns {@code true} when {@code chain} (leaf-first, excluding the trust anchor) validates to
   * one of {@code trustAnchors}. Returns {@code false} — never throws — when the chain is empty,
   * the anchor set is empty, or PKIX validation fails for any reason.
   */
  public static boolean validates(List<X509Certificate> chain, Set<TrustAnchor> trustAnchors) {
    if (chain.isEmpty() || trustAnchors.isEmpty()) {
      return false;
    }
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      CertPath certPath = cf.generateCertPath(chain);
      PKIXParameters params = new PKIXParameters(trustAnchors);
      params.setRevocationEnabled(false);
      CertPathValidator.getInstance("PKIX").validate(certPath, params);
      return true;
    } catch (Exception e) {
      // Any PKIX failure — untrusted root, expired cert, broken chain — means "not trusted".
      return false;
    }
  }
}
