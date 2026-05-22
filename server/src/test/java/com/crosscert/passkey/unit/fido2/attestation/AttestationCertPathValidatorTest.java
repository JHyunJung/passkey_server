package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.attestation.AttestationCertPathValidator;
import com.crosscert.passkey.unit.fido2.mds.MdsTestFixtures;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AttestationCertPathValidatorTest {

  @Test
  void validates_chain_to_trusted_root() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    // leaf (signingCert) is issued by rootCa — chain [leaf] validates against root anchor.
    boolean ok =
        AttestationCertPathValidator.validates(
            List.of(pki.signingCert()), Set.of(new TrustAnchor(pki.rootCa(), null)));
    assertThat(ok).isTrue();
  }

  @Test
  void rejects_chain_against_wrong_root() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    MdsTestFixtures.Pki other = MdsTestFixtures.buildPki();
    boolean ok =
        AttestationCertPathValidator.validates(
            List.of(pki.signingCert()), Set.of(new TrustAnchor(other.rootCa(), null)));
    assertThat(ok).isFalse();
  }

  @Test
  void rejects_empty_anchor_set() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    boolean ok = AttestationCertPathValidator.validates(List.of(pki.signingCert()), Set.of());
    assertThat(ok).isFalse();
  }

  @Test
  void rejects_empty_chain() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    boolean ok =
        AttestationCertPathValidator.validates(
            List.<X509Certificate>of(), Set.of(new TrustAnchor(pki.rootCa(), null)));
    assertThat(ok).isFalse();
  }
}
