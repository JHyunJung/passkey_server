package com.crosscert.passkey.unit.credential.metadata;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.unit.fido2.mds.MdsTestFixtures;
import org.junit.jupiter.api.Test;

/**
 * Verifies MdsBlobProvider's in-house parsing path. Full Spring wiring (RestClient, root CA
 * resource) is covered by the Phase 3 integration test; this unit test pins the BLOB-to-source
 * transformation.
 */
class MdsBlobProviderTest {

  @Test
  void parses_blob_into_trust_anchor_source() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String payload =
        "{\"no\":1,\"nextUpdate\":\"2099-01-01\",\"entries\":["
            + "{\"aaguid\":\"00000000-0000-0000-0000-00000000000a\","
            + "\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\"}],"
            + "\"metadataStatement\":{\"attestationRootCertificates\":[]}}]}";
    String jws = MdsTestFixtures.signBlob(payload, pki);

    com.crosscert.passkey.fido2.mds.MetadataBlob blob =
        com.crosscert.passkey.fido2.mds.MetadataBlob.parse(jws, pki.rootCa());
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource source =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(blob.entries());

    assertThat(source.findEntry(java.util.UUID.fromString("00000000-0000-0000-0000-00000000000a")))
        .isPresent();
  }
}
