package com.crosscert.passkey.credential.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebAuthnConfig {

  /**
   * Non-strict manager — skips attestation cert chain validation. Used by tenants whose policy has
   * {@code mdsStrict=false} (default). Always available regardless of MDS configuration. Marked
   * {@code @Primary} so callers that don't qualify still resolve a manager.
   */
  @Bean(name = "nonStrictWebAuthnManager")
  @org.springframework.context.annotation.Primary
  public WebAuthnManager nonStrictWebAuthnManager() {
    return WebAuthnManager.createNonStrictWebAuthnManager();
  }

  /**
   * Strict manager — validates attestation cert chains against MDS-sourced trust anchors. Only
   * registered when an MDS-backed {@link TrustAnchorRepository} is available ({@code
   * passkey.mds.enabled=true}). Tenants with {@code mdsStrict=true} require this bean — absence
   * causes {@code MDS_UNAVAILABLE} at register time (fail-closed).
   */
  @Bean(name = "strictWebAuthnManager")
  @ConditionalOnBean(TrustAnchorRepository.class)
  public WebAuthnManager strictWebAuthnManager(TrustAnchorRepository trustAnchorRepository) {
    List<AttestationStatementVerifier> verifiers =
        List.of(
            new NoneAttestationStatementVerifier(),
            new PackedAttestationStatementVerifier(),
            new TPMAttestationStatementVerifier(),
            new AndroidKeyAttestationStatementVerifier(),
            new AndroidSafetyNetAttestationStatementVerifier(),
            new FIDOU2FAttestationStatementVerifier(),
            new AppleAnonymousAttestationStatementVerifier());
    DefaultCertPathTrustworthinessVerifier certPathVerifier =
        new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository);
    DefaultSelfAttestationTrustworthinessVerifier selfAttVerifier =
        new DefaultSelfAttestationTrustworthinessVerifier();
    return new WebAuthnManager(verifiers, certPathVerifier, selfAttVerifier, new ObjectConverter());
  }
}
