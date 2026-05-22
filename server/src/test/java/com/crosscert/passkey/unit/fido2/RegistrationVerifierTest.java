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
}
