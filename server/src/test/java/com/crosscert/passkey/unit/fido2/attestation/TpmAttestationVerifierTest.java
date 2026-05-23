package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.TpmAttestationVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

class TpmAttestationVerifierTest {

  private final TpmAttestationVerifier verifier = new TpmAttestationVerifier();

  @Test
  void verifies_valid_tpm2_rsa_attestation_non_strict() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), null);

    assertThat(result.format()).isEqualTo("tpm");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void verifies_valid_tpm2_ecc_attestation_non_strict() throws Exception {
    TpmFixture f = TpmFixture.validEcc("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), null);

    assertThat(result.format()).isEqualTo("tpm");
  }

  @Test
  void rejects_tpm_1_2_with_invalid_attestation_format() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withVer("1.2");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.INVALID_ATTESTATION_FORMAT);
  }

  @Test
  void rejects_when_pubarea_does_not_match_credential_key() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withMismatchedPubArea();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_extra_data_does_not_match_hash() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withTamperedExtraData();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_attested_name_does_not_match_pubarea_hash() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withTamperedAttestedName();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_aik_cert_missing_eku() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withoutAikEku();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_aik_cert_missing_tpm_san() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withoutTpmSan();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  // ── strict 모드 (3건 — Task 1 review 교훈 반영) ────────────────────────────────────────────────

  @Test
  void strict_rejects_unknown_aaguid() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    var emptySource = new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), emptySource))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.MDS_TRUST_FAILED);
  }

  @Test
  void strict_rejects_revoked_aaguid() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    var aaguid = java.util.UUID.fromString("00000000-0000-0000-0000-000000000000");
    var entry =
        new com.crosscert.passkey.fido2.mds.MetadataEntry(
            aaguid,
            java.util.List.of(f.aikCert()),
            java.util.List.of(com.crosscert.passkey.fido2.mds.StatusReport.REVOKED));
    var source = new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of(entry));

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), source))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.AUTHENTICATOR_REVOKED);
  }

  @Test
  void strict_passes_with_matching_trust_anchor() throws Exception {
    var caKey = TpmFixture.rsaKeyPair();
    var caCert = TpmFixture.selfSignedCa("CN=TPM Test CA", caKey);
    TpmFixture f = TpmFixture.withCa(caKey, caCert, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    var aaguid = java.util.UUID.fromString("00000000-0000-0000-0000-000000000000");
    var entry =
        new com.crosscert.passkey.fido2.mds.MetadataEntry(
            aaguid,
            java.util.List.of(caCert),
            java.util.List.of(com.crosscert.passkey.fido2.mds.StatusReport.FIDO_CERTIFIED));
    var source = new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(java.util.List.of(entry));

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), source);

    assertThat(result.format()).isEqualTo("tpm");
    assertThat(result.trustPathPresent()).isTrue();
  }

  @Test
  void rejects_unsupported_alg_with_unsupported_algorithm_reason() throws Exception {
    // alg = -65535 (RS1 / SHA1withRSA) is not listed in WebAuthn L3 §8.3 for tpm.
    TpmFixture f = TpmFixture.validRsa("example.com").withAlg(-65535L);
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UNSUPPORTED_ALGORITHM);
  }

  @Test
  void rejects_when_signature_invalid_with_signature_invalid_reason() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withTamperedSignature();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.SIGNATURE_INVALID);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }
}
