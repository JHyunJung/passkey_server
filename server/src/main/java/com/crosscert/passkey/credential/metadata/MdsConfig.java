package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the in-house {@link MdsTrustAnchorSource} for the self-implemented strict attestation path.
 * The bean is a thin accessor over {@link MdsBlobProvider}, which holds the live source and swaps
 * it on each refresh — so callers always see the latest BLOB without rebuilding the bean.
 *
 * <p>Phase 3: this bean coexists with the webauthn4j {@code TrustAnchorRepository} (wired by {@code
 * MdsTrustAnchorRepositoryConfig}); Phase 4 removes the webauthn4j wiring once the strict
 * registration path no longer uses webauthn4j.
 */
@Configuration
@ConditionalOnBean(MdsBlobProvider.class)
public class MdsConfig {

  /**
   * A supplier-style bean returning the current trust anchor source. {@code RegistrationService}
   * (Phase 4) calls this to obtain strict-mode trust anchors; until then it is available for
   * integration tests.
   */
  @Bean
  public MdsTrustAnchorSourceHolder mdsTrustAnchorSourceHolder(MdsBlobProvider provider) {
    return provider::currentTrustAnchorSource;
  }

  /** Functional holder so callers depend on an interface, not on {@code MdsBlobProvider}. */
  @FunctionalInterface
  public interface MdsTrustAnchorSourceHolder {
    /** The current trust anchor source, or null before the first successful BLOB refresh. */
    MdsTrustAnchorSource current();
  }
}
