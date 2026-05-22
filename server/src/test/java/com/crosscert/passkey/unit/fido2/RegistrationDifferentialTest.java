package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Differential test: verifies that the self-core {@link RegistrationVerifier} and webauthn4j {@link
 * WebAuthnManager} produce identical results for the same registration input — both for "none" and
 * "packed" self-attestation formats. This is the safety net guarding the migration until webauthn4j
 * is dropped from the non-strict path.
 */
class RegistrationDifferentialTest {

  private static final String ORIGIN = "https://example.com";
  private static final String RP_ID = "example.com";

  @Test
  void self_core_and_webauthn4j_agree_on_none_registration() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("none", ORIGIN, RP_ID);

    // Self-core result
    RegistrationVerificationResult selfResult = verifySelfCore(reg);

    // webauthn4j result
    W4jResult w4j = verifyWebauthn4j(reg);

    assertThat(selfResult.credentialId())
        .as("credentialId: self-core vs webauthn4j")
        .isEqualTo(w4j.credentialId);
    assertThat(selfResult.signCount())
        .as("signCount: self-core vs webauthn4j")
        .isEqualTo(w4j.signCount);
    assertThat(selfResult.backupEligible())
        .as("backupEligible: self-core vs webauthn4j")
        .isEqualTo(w4j.backupEligible);
    assertThat(selfResult.backupState())
        .as("backupState: self-core vs webauthn4j")
        .isEqualTo(w4j.backupState);

    // Sanity-check fixture values
    assertThat(selfResult.signCount()).isEqualTo(0L);
    assertThat(selfResult.backupEligible()).isFalse();
    assertThat(selfResult.backupState()).isFalse();
  }

  @Test
  void self_core_and_webauthn4j_agree_on_packed_registration() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("packed", ORIGIN, RP_ID);

    // Self-core result
    RegistrationVerificationResult selfResult = verifySelfCore(reg);

    // webauthn4j result
    W4jResult w4j = verifyWebauthn4j(reg);

    assertThat(selfResult.credentialId())
        .as("credentialId: self-core vs webauthn4j")
        .isEqualTo(w4j.credentialId);
    assertThat(selfResult.signCount())
        .as("signCount: self-core vs webauthn4j")
        .isEqualTo(w4j.signCount);
    assertThat(selfResult.backupEligible())
        .as("backupEligible: self-core vs webauthn4j")
        .isEqualTo(w4j.backupEligible);
    assertThat(selfResult.backupState())
        .as("backupState: self-core vs webauthn4j")
        .isEqualTo(w4j.backupState);

    // Sanity-check fixture values
    assertThat(selfResult.signCount()).isEqualTo(0L);
    assertThat(selfResult.backupEligible()).isFalse();
    assertThat(selfResult.backupState()).isFalse();
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

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
        acd.getCredentialId(),
        data.getAttestationObject().getAuthenticatorData().getSignCount(),
        data.getAttestationObject().getAuthenticatorData().isFlagBE(),
        data.getAttestationObject().getAuthenticatorData().isFlagBS());
  }

  private record W4jResult(
      byte[] credentialId, long signCount, boolean backupEligible, boolean backupState) {}
}
