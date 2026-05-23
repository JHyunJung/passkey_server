package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.FidoMDS3MetadataBLOBProvider;
import com.webauthn4j.metadata.MetadataBLOBProvider;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Thin wrapper around webauthn4j's {@link FidoMDS3MetadataBLOBProvider}. The webauthn4j class
 * already handles HTTPS fetch, JWT signature verification against the FIDO Alliance Global Root CA,
 * and in-memory caching keyed by next-update. We add: (a) lazy boot warm-up, (b) snapshot accessor
 * for the {@code /_diag/mds-status} endpoint, (c) lifecycle logging.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "passkey.mds", name = "enabled", havingValue = "true")
public class MdsBlobProvider implements MetadataBLOBProvider {

  private final MdsProperties props;
  private final FidoMDS3MetadataBLOBProvider delegate;

  // --- Phase 3: in-house MDS parsing alongside the webauthn4j delegate. ---
  private final RestClient restClient;
  private final X509Certificate rootCa;
  private final AtomicReference<MdsTrustAnchorSource> trustAnchorSource = new AtomicReference<>();

  @Getter private final AtomicReference<Instant> lastFetched = new AtomicReference<>();
  @Getter private final AtomicReference<MetadataBLOB> lastBlob = new AtomicReference<>();

  @Autowired
  public MdsBlobProvider(MdsProperties props, ResourceLoader resourceLoader) {
    this.props = props;
    this.rootCa = loadRootCa(resourceLoader);
    this.delegate =
        new FidoMDS3MetadataBLOBProvider(new ObjectConverter(), props.getBlobUrl(), this.rootCa);
    this.restClient = RestClient.create();
    log.info(
        "mds.provider.constructed url={} rootCaSubject={}",
        props.getBlobUrl(),
        rootCa.getSubjectX500Principal().getName());
  }

  @PostConstruct
  void warmUp() {
    try {
      refresh();
    } catch (Exception e) {
      // fail-open: strict tenants get MDS_UNAVAILABLE until next scheduled refresh succeeds
      log.error("mds.warmup.failed reason={}", e.getMessage(), e);
    }
  }

  /** Force a fetch + verify of the latest BLOB. Called by {@code MdsRefreshScheduler}. */
  public synchronized void refresh() {
    delegate.refresh();
    MetadataBLOB blob = delegate.provide();
    MetadataBLOBPayload payload = blob.getPayload();
    lastBlob.set(blob);
    lastFetched.set(Instant.now());
    log.info(
        "mds.refresh.success entries={} nextUpdate={} serialNumber={}",
        payload.getEntries().size(),
        payload.getNextUpdate(),
        payload.getNo());
    if (log.isDebugEnabled()) {
      for (MetadataBLOBPayloadEntry e : payload.getEntries()) {
        if (e.getStatusReports() != null
            && e.getStatusReports().stream()
                .anyMatch(r -> r.getStatus() != null && r.getStatus().name().contains("UPDATE"))) {
          log.debug(
              "mds.entry.update_available aaguid={} reports={}",
              e.getAaguid(),
              e.getStatusReports().size());
        }
      }
    }
    refreshInHouse();
  }

  /**
   * Fetch the BLOB JWS and parse it with the in-house {@code fido2.mds} parser, swapping in a fresh
   * {@link MdsTrustAnchorSource}. Called from {@link #refresh()} alongside the webauthn4j delegate
   * refresh. Failures are logged but do not propagate — the stale in-house source is kept (same
   * fail-soft policy as the webauthn4j delegate).
   */
  private void refreshInHouse() {
    try {
      String jws = restClient.get().uri(props.getBlobUrl()).retrieve().body(String.class);
      MetadataBlob blob = MetadataBlob.parse(jws, rootCa);
      trustAnchorSource.set(new MdsTrustAnchorSource(blob.entries()));
      log.info("mds.inhouse.refresh.success entries={}", blob.entries().size());
    } catch (Exception e) {
      // fail-soft: keep the stale in-house source, same policy as the webauthn4j delegate.
      log.error("mds.inhouse.refresh.failed reason={}", e.getMessage(), e);
    }
  }

  /** The current in-house trust anchor source, or null before the first successful refresh. */
  public MdsTrustAnchorSource currentTrustAnchorSource() {
    return trustAnchorSource.get();
  }

  @Override
  public MetadataBLOB provide() {
    // Defensive: warm-up failure leaves lastBlob null; the webauthn4j delegate may also return null
    // before its internal cache is populated. Strict tenants must fail-closed with MDS_UNAVAILABLE
    // rather than NPE somewhere deep inside the trust-anchor resolver.
    MetadataBLOB blob = delegate.provide();
    if (blob == null) {
      log.error("mds.provide.unavailable cause=blob_not_yet_fetched");
      throw new BusinessException(ErrorCode.MDS_UNAVAILABLE);
    }
    return blob;
  }

  private X509Certificate loadRootCa(ResourceLoader resourceLoader) {
    Resource resource = resourceLoader.getResource(props.getRootCertificatePath());
    if (!resource.exists()) {
      throw new IllegalStateException(
          "FIDO MDS root certificate not found at " + props.getRootCertificatePath());
    }
    try (InputStream in = resource.getInputStream()) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(in);
    } catch (Exception e) {
      throw new IllegalStateException(
          "failed to load FIDO MDS root certificate from " + props.getRootCertificatePath(), e);
    }
  }
}
