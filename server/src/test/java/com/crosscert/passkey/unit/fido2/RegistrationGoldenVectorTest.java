package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Golden-vector tests for {@link RegistrationVerifier}. Replaces the webauthn4j-based differential
 * tests with self-built deterministic vectors. The fixtures (built via BouncyCastle-compatible JCA
 * in {@link Fido2Fixtures}) constitute the golden inputs; each test asserts the verifier produces
 * the expected facts.
 *
 * <p>Future: extend with W3C L3 spec examples and FIDO conformance vectors (Phase 5 backlog, see
 * docs/superpowers/specs §11.3).
 */
class RegistrationGoldenVectorTest {

  private static final String ORIGIN = "https://example.com";
  private static final String RP_ID = "example.com";

  // ── Positive cases ─────────────────────────────────────────────────────────

  @Test
  void none_attestation_self_built_vector_verifies() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("none", ORIGIN, RP_ID);

    RegistrationVerificationResult result = verify(reg);

    assertThat(result.attestationFormat()).isEqualTo("none");
    assertThat(result.credentialId()).isEqualTo(reg.credentialId());
    assertThat(result.signCount()).isEqualTo(reg.signCount());
    assertThat(result.aaguid()).hasSize(16);
    assertThat(result.backupEligible()).isFalse();
    assertThat(result.backupState()).isFalse();
    assertThat(result.userVerified()).isTrue();
    assertThat(result.crossOrigin()).isFalse();
  }

  @Test
  void packed_self_attestation_self_built_vector_verifies() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("packed", ORIGIN, RP_ID);

    RegistrationVerificationResult result = verify(reg);

    assertThat(result.attestationFormat()).isEqualTo("packed");
    assertThat(result.credentialId()).isEqualTo(reg.credentialId());
    assertThat(result.signCount()).isEqualTo(reg.signCount());
    assertThat(result.aaguid()).hasSize(16);
  }

  @Test
  void attested_credential_data_round_trips_through_parse_golden() throws Exception {
    // The attestedCredentialData blob produced by RegistrationVerifier must be parseable back
    // by AttestedCredentialData.parse() — this is load-bearing: it is stored in
    // credential.public_key_cose and later read by AuthenticationVerifier.
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("none", ORIGIN, RP_ID);

    RegistrationVerificationResult result = verify(reg);

    com.crosscert.passkey.fido2.model.AttestedCredentialData parsed =
        com.crosscert.passkey.fido2.model.AttestedCredentialData.parse(
            result.attestedCredentialData());
    assertThat(parsed.credentialId()).isEqualTo(result.credentialId());
    assertThat(parsed.aaguid()).isEqualTo(result.aaguid());
  }

  // ── Negative cases — golden rejection vectors ──────────────────────────────

  @Test
  void golden_vector_rejects_challenge_mismatch() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("none", ORIGIN, RP_ID);
    byte[] wrongChallenge = "d3JvbmctY2hhbGxlbmdl".getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            reg.attestationObject(),
                            reg.clientDataJson(),
                            wrongChallenge,
                            List.of(ORIGIN),
                            RP_ID,
                            false,
                            null)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(Fido2VerificationException.FailureReason.CHALLENGE_MISMATCH);
  }

  @Test
  void golden_vector_rejects_origin_mismatch() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("none", ORIGIN, RP_ID);

    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            reg.attestationObject(),
                            reg.clientDataJson(),
                            reg.challenge(),
                            List.of("https://other.com"),
                            RP_ID,
                            false,
                            null)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(Fido2VerificationException.FailureReason.ORIGIN_MISMATCH);
  }

  // ── Helper ────────────────────────────────────────────────────────────────

  private static RegistrationVerificationResult verify(Fido2Fixtures.Registration reg)
      throws Exception {
    return new RegistrationVerifier()
        .verify(
            new RegistrationVerificationRequest(
                reg.attestationObject(),
                reg.clientDataJson(),
                reg.challenge(),
                List.of(ORIGIN),
                RP_ID,
                false,
                null));
  }
}
