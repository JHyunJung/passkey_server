package com.crosscert.passkey.unit.fido2.mds;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.mds.MdsException;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MetadataBlobTest {

  // A minimal MDS3 payload: one entry with an AAGUID and a FIDO_CERTIFIED status.
  private static final String SAMPLE_PAYLOAD =
      "{\"no\":42,\"nextUpdate\":\"2099-01-01\",\"entries\":["
          + "{\"aaguid\":\"00000000-0000-0000-0000-000000000001\","
          + "\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\"}],"
          + "\"metadataStatement\":{\"attestationRootCertificates\":[]}}"
          + "]}";

  @Test
  void parses_a_valid_signed_blob() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob(SAMPLE_PAYLOAD, pki);

    MetadataBlob blob = MetadataBlob.parse(jws, pki.rootCa());
    assertThat(blob.entries()).hasSize(1);
    MetadataEntry entry = blob.entries().get(0);
    assertThat(entry.aaguid()).isEqualTo(UUID.fromString("00000000-0000-0000-0000-000000000001"));
    assertThat(entry.isRevoked()).isFalse();
  }

  @Test
  void rejects_blob_signed_by_untrusted_root() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    MdsTestFixtures.Pki otherPki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob(SAMPLE_PAYLOAD, pki);

    // Verify against a different root CA — the x5c chain does not chain to it.
    assertThatThrownBy(() -> MetadataBlob.parse(jws, otherPki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_blob_with_tampered_payload() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob(SAMPLE_PAYLOAD, pki);
    // Corrupt the payload segment (middle of the three dot-separated JWS parts).
    String[] parts = jws.split("\\.");
    String tampered = parts[0] + "." + parts[1] + "x." + parts[2];

    assertThatThrownBy(() -> MetadataBlob.parse(tampered, pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_malformed_jws() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    assertThatThrownBy(() -> MetadataBlob.parse("not-a-jws", pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_blob_with_algorithm_confusion() throws Exception {
    // An attacker keeps the RSA x5c chain but forges the header alg to HS256, hoping the verifier
    // treats the RSA public key as an HMAC secret. The verifier must reject this.
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String forged =
        MdsTestFixtures.signBlobWithAlgorithm(
            SAMPLE_PAYLOAD, pki, com.nimbusds.jose.JWSAlgorithm.HS256);
    assertThatThrownBy(() -> MetadataBlob.parse(forged, pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_blob_signed_by_non_rsa_certificate() throws Exception {
    // The BLOB signing leaf has an EC key — MDS BLOBs are RS256-signed, so this must be rejected.
    MdsTestFixtures.Pki ecPki = MdsTestFixtures.buildEcSigningPki();
    // Sign with RS256 header but an EC leaf cert — the verifier rejects at the RSA-key check.
    String jws =
        MdsTestFixtures.signBlobWithAlgorithm(
            SAMPLE_PAYLOAD, ecPki, com.nimbusds.jose.JWSAlgorithm.RS256);
    assertThatThrownBy(() -> MetadataBlob.parse(jws, ecPki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_blob_with_no_x5c_header() throws Exception {
    // A JWS with no x5c header — there is no certificate chain to verify against.
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    com.nimbusds.jose.JWSObject jws =
        new com.nimbusds.jose.JWSObject(
            new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256).build(),
            new com.nimbusds.jose.Payload(SAMPLE_PAYLOAD));
    jws.sign(new com.nimbusds.jose.crypto.RSASSASigner(pki.signingKey()));
    String noX5c = jws.serialize();
    assertThatThrownBy(() -> MetadataBlob.parse(noX5c, pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_blob_payload_without_entries_array() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob("{\"no\":1,\"nextUpdate\":\"2099-01-01\"}", pki);
    assertThatThrownBy(() -> MetadataBlob.parse(jws, pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }
}
