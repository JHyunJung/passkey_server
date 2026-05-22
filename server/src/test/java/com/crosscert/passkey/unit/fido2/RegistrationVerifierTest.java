package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import java.util.List;
import org.junit.jupiter.api.Test;

class RegistrationVerifierTest {

  @Test
  void verifies_a_valid_none_attestation_registration() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    RegistrationVerificationResult result =
        new RegistrationVerifier()
            .verify(
                new RegistrationVerificationRequest(
                    r.attestationObject(),
                    r.clientDataJson(),
                    r.challenge(),
                    List.of("https://example.com"),
                    "example.com",
                    false));
    assertThat(result.attestationFormat()).isEqualTo("none");
    assertThat(result.credentialId()).isEqualTo(r.credentialId());
    assertThat(result.signCount()).isEqualTo(r.signCount());
  }

  @Test
  void verifies_a_valid_packed_attestation_registration() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    RegistrationVerificationResult result =
        new RegistrationVerifier()
            .verify(
                new RegistrationVerificationRequest(
                    r.attestationObject(),
                    r.clientDataJson(),
                    r.challenge(),
                    List.of("https://example.com"),
                    "example.com",
                    false));
    assertThat(result.attestationFormat()).isEqualTo("packed");
  }

  @Test
  void rejects_wrong_ceremony_type() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.registrationWithClientType(
            "webauthn.get", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.WRONG_CEREMONY_TYPE);
  }

  @Test
  void rejects_challenge_mismatch() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            "d3Jvbmc".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                            List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.CHALLENGE_MISMATCH);
  }

  @Test
  void rejects_origin_mismatch() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://other.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ORIGIN_MISMATCH);
  }

  @Test
  void rejects_rp_id_hash_mismatch() throws Exception {
    // fixture는 rpId "example.com"으로 rpIdHash를 만들지만 expectedRpId는 다른 값.
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://example.com"),
                            "other-rp.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.RPID_HASH_MISMATCH);
  }

  @Test
  void rejects_missing_up_flag() throws Exception {
    // flags에서 UP(0x01) 제거, UV|AT(0x44)만.
    Fido2Fixtures.Registration r =
        Fido2Fixtures.registrationWithFlags(0x44, "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UP_FLAG_MISSING);
  }

  @Test
  void rejects_uv_required_but_flag_missing() throws Exception {
    // flags = UP|AT(0x41) — UV 비트 없음. userVerificationRequired=true로 요청.
    Fido2Fixtures.Registration r =
        Fido2Fixtures.registrationWithFlags(0x41, "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://example.com"),
                            "example.com",
                            true)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UV_FLAG_REQUIRED);
  }

  @Test
  void rejects_malformed_attestation_object() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            new byte[] {0x01, 0x02}, // 잘린 CBOR
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.MALFORMED_CBOR);
  }

  @Test
  void rejects_null_inputs() {
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(null, null, null, null, null, false)))
        .isInstanceOf(Fido2VerificationException.class);
  }

  @Test
  void attested_credential_data_round_trips_through_parse() throws Exception {
    // RegistrationVerifier가 직렬화한 attestedCredentialData를 AttestedCredentialData.parse()로
    // 되읽어 aaguid/credentialId가 일치하는지 — 직렬화 형식이 load-bearing이므로 회귀 방어.
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    RegistrationVerificationResult result =
        new RegistrationVerifier()
            .verify(
                new RegistrationVerificationRequest(
                    r.attestationObject(),
                    r.clientDataJson(),
                    r.challenge(),
                    List.of("https://example.com"),
                    "example.com",
                    false));
    com.crosscert.passkey.fido2.model.AttestedCredentialData parsed =
        com.crosscert.passkey.fido2.model.AttestedCredentialData.parse(
            result.attestedCredentialData());
    assertThat(parsed.credentialId()).isEqualTo(result.credentialId());
    assertThat(parsed.aaguid()).isEqualTo(result.aaguid());
  }
}
