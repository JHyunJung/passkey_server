package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RegistrationVerifierStrictTest {

  @Test
  void passes_non_strict_when_trust_anchors_null() throws Exception {
    Fido2Fixtures.Registration reg =
        Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(),
            reg.clientDataJson(),
            reg.challenge(),
            List.of("https://example.com"),
            "example.com",
            false,
            /*trustAnchors*/ null);

    RegistrationVerificationResult result = new RegistrationVerifier().verify(req);

    assertThat(result.attestationFormat()).isEqualTo("packed");
  }

  @Test
  void rejects_strict_when_aaguid_not_in_mds() throws Exception {
    Fido2Fixtures.Registration reg =
        Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    MdsTrustAnchorSource emptySource = new MdsTrustAnchorSource(List.of());

    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(),
            reg.clientDataJson(),
            reg.challenge(),
            List.of("https://example.com"),
            "example.com",
            false,
            emptySource);

    assertThatThrownBy(() -> new RegistrationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isIn(FailureReason.MDS_TRUST_FAILED, FailureReason.TRUST_PATH_INVALID);
  }

  @Test
  void rejects_strict_when_packed_self_aaguid_revoked() throws Exception {
    Fido2Fixtures.Registration reg =
        Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    // Fido2Fixtures uses all-zeros AAGUID for packed self-attestation.
    UUID aaguid = UUID.fromString("00000000-0000-0000-0000-000000000000");
    MetadataEntry revokedEntry =
        new MetadataEntry(aaguid, List.of(), List.of(StatusReport.REVOKED));
    MdsTrustAnchorSource source = new MdsTrustAnchorSource(List.of(revokedEntry));

    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(),
            reg.clientDataJson(),
            reg.challenge(),
            List.of("https://example.com"),
            "example.com",
            false,
            source);

    assertThatThrownBy(() -> new RegistrationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.AUTHENTICATOR_REVOKED);
  }
}
