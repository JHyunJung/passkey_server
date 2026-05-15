package com.crosscert.passkey.credential.metadata;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.metadata.anchor.MetadataBLOBBasedTrustAnchorRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link TrustAnchorRepository} bean used by the strict {@code WebAuthnManager}. The
 * underlying {@link MetadataBLOBBasedTrustAnchorRepository} resolves trust anchors per-AAGUID from
 * the current BLOB on every {@code find()} call, so refresh propagates without rebuilding the bean.
 *
 * <p>StatusReport policy: {@code notFidoCertifiedAllowed=true} — per plan decision, only
 * REVOKED/COMPROMISED-class statuses block; non-certified entries pass with a WARN log emitted in
 * {@link MdsBlobProvider#refresh()}.
 */
@Configuration
@ConditionalOnBean(MdsBlobProvider.class)
public class MdsTrustAnchorRepositoryConfig {

  @Bean
  public TrustAnchorRepository trustAnchorRepository(
      MdsBlobProvider provider, MdsProperties props) {
    MetadataBLOBBasedTrustAnchorRepository repo =
        new MetadataBLOBBasedTrustAnchorRepository(provider);
    repo.setNotFidoCertifiedAllowed(props.isAllowNotFidoCertified());
    return repo;
  }
}
