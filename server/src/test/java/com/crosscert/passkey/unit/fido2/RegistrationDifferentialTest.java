package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Differential test: verifies that the self-core {@link RegistrationVerifier} and webauthn4j {@link
 * WebAuthnManager} produce identical results for the same registration input — both for "none" and
 * "packed" self-attestation formats, and that both reject the same bad input (challenge / origin
 * mismatch). This is the safety net guarding the migration until webauthn4j is dropped from the
 * non-strict path.
 */
class RegistrationDifferentialTest {

  private static final String ORIGIN = "https://example.com";
  private static final String RP_ID = "example.com";

  private final AttestedCredentialDataConverter acdConverter =
      new AttestedCredentialDataConverter(new ObjectConverter());

  // ── Positive cases ─────────────────────────────────────────────────────────

  @Test
  void self_core_and_webauthn4j_agree_on_none_registration() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("none", ORIGIN, RP_ID);

    RegistrationVerificationResult selfResult = verifySelfCore(reg);
    W4jResult w4j = verifyWebauthn4j(reg);

    assertResultsAgree(selfResult, w4j);
  }

  @Test
  void self_core_and_webauthn4j_agree_on_packed_registration() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("packed", ORIGIN, RP_ID);

    RegistrationVerificationResult selfResult = verifySelfCore(reg);
    W4jResult w4j = verifyWebauthn4j(reg);

    assertResultsAgree(selfResult, w4j);
  }

  // ── Negative cases — both implementations must reject the same bad input ───

  @Test
  void self_core_and_webauthn4j_both_reject_challenge_mismatch() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    byte[] wrongChallenge = "d3JvbmctY2hhbGxlbmdl".getBytes(StandardCharsets.UTF_8);
    // 자체 코어
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            wrongChallenge,
                            java.util.List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class);
    // webauthn4j — 다른 challenge로 ServerProperty 구성
    WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();
    assertThatThrownBy(
            () -> {
              RegistrationData data =
                  manager.parse(new RegistrationRequest(r.attestationObject(), r.clientDataJson()));
              manager.verify(
                  data,
                  new RegistrationParameters(
                      new ServerProperty(
                          java.util.Set.of(new Origin("https://example.com")),
                          "example.com",
                          new DefaultChallenge(wrongChallenge)),
                      null,
                      false,
                      true));
            })
        .isInstanceOf(Exception.class);
  }

  @Test
  void self_core_and_webauthn4j_both_reject_origin_mismatch() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    // 자체 코어 — expectedOrigins에 fixture origin 없음
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            java.util.List.of("https://other.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class);
    // webauthn4j — 다른 origin으로 ServerProperty 구성
    WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();
    assertThatThrownBy(
            () -> {
              RegistrationData data =
                  manager.parse(new RegistrationRequest(r.attestationObject(), r.clientDataJson()));
              manager.verify(
                  data,
                  new RegistrationParameters(
                      new ServerProperty(
                          java.util.Set.of(new Origin("https://other.com")),
                          "example.com",
                          new DefaultChallenge(r.challenge())),
                      null,
                      false,
                      true));
            })
        .isInstanceOf(Exception.class);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private void assertResultsAgree(RegistrationVerificationResult selfResult, W4jResult w4j) {
    assertThat(selfResult.credentialId())
        .as("credentialId: self-core vs webauthn4j")
        .isEqualTo(w4j.acd.getCredentialId());
    assertThat(selfResult.signCount())
        .as("signCount: self-core vs webauthn4j")
        .isEqualTo(w4j.signCount);
    assertThat(selfResult.backupEligible())
        .as("backupEligible: self-core vs webauthn4j")
        .isEqualTo(w4j.backupEligible);
    assertThat(selfResult.backupState())
        .as("backupState: self-core vs webauthn4j")
        .isEqualTo(w4j.backupState);

    // attestedCredentialData 블롭 동등성 — DB에 저장되고 인증 시 역직렬화되므로 핵심.
    assertThat(selfResult.attestedCredentialData())
        .as("attestedCredentialData blob: self-core vs webauthn4j")
        .isEqualTo(acdConverter.convert(w4j.acd));
    // aaguid 동등성 — 둘 다 16바이트 raw 형식.
    assertThat(selfResult.aaguid())
        .as("aaguid: self-core vs webauthn4j")
        .isEqualTo(w4j.acd.getAaguid() == null ? null : w4j.acd.getAaguid().getBytes());

    // Sanity-check fixture values.
    assertThat(selfResult.signCount()).isEqualTo(0L);
    assertThat(selfResult.backupEligible()).isFalse();
    assertThat(selfResult.backupState()).isFalse();
  }

  private static RegistrationVerificationResult verifySelfCore(Fido2Fixtures.Registration reg)
      throws Exception {
    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(),
            reg.clientDataJson(),
            reg.challenge(),
            List.of(ORIGIN),
            RP_ID,
            false);
    return new RegistrationVerifier().verify(req);
  }

  private static W4jResult verifyWebauthn4j(Fido2Fixtures.Registration reg) {
    WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();
    RegistrationRequest regReq =
        new RegistrationRequest(reg.attestationObject(), reg.clientDataJson());
    ServerProperty serverProperty =
        new ServerProperty(
            Set.of(new Origin(ORIGIN)), RP_ID, new DefaultChallenge(reg.challenge()));
    RegistrationParameters params = new RegistrationParameters(serverProperty, null, false, true);
    RegistrationData data = manager.parse(regReq);
    manager.verify(data, params);

    AttestedCredentialData acd =
        data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    return new W4jResult(
        acd,
        data.getAttestationObject().getAuthenticatorData().getSignCount(),
        data.getAttestationObject().getAuthenticatorData().isFlagBE(),
        data.getAttestationObject().getAuthenticatorData().isFlagBS());
  }

  private record W4jResult(
      AttestedCredentialData acd, long signCount, boolean backupEligible, boolean backupState) {}
}
