package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
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
 * Fetches, verifies, and caches the FIDO MDS3 metadata BLOB using the in-house {@code fido2.mds}
 * parser. Provides: (a) lazy boot warm-up, (b) snapshot accessors for the {@code /_diag/mds-status}
 * endpoint, (c) lifecycle logging, and (d) a live {@link MdsTrustAnchorSource} used by the strict
 * attestation path.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "passkey.mds", name = "enabled", havingValue = "true")
public class MdsBlobProvider {

  private final MdsProperties props;
  private final RestClient restClient;
  private final X509Certificate rootCa;
  private final AtomicReference<MdsTrustAnchorSource> trustAnchorSource = new AtomicReference<>();

  @Getter private final AtomicReference<Instant> lastFetched = new AtomicReference<>();
  @Getter private final AtomicReference<MetadataBlob> lastBlob = new AtomicReference<>();

  @Autowired
  public MdsBlobProvider(MdsProperties props, ResourceLoader resourceLoader) {
    this.props = props;
    this.rootCa = loadRootCa(resourceLoader);
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
    try {
      String jws = restClient.get().uri(props.getBlobUrl()).retrieve().body(String.class);
      MetadataBlob blob = MetadataBlob.parse(jws, rootCa);
      trustAnchorSource.set(new MdsTrustAnchorSource(blob.entries()));
      lastBlob.set(blob);
      lastFetched.set(Instant.now());
      log.info(
          "mds.refresh.success entries={} nextUpdate={} serialNumber={}",
          blob.entries().size(),
          blob.nextUpdate(),
          blob.serialNumber());
      if (log.isDebugEnabled()) {
        for (com.crosscert.passkey.fido2.mds.MetadataEntry e : blob.entries()) {
          if (e.statusReports() != null
              && e.statusReports().stream()
                  .anyMatch(r -> r != null && r.name().contains("UPDATE"))) {
            log.debug(
                "mds.entry.update_available aaguid={} statusCount={}",
                e.aaguid(),
                e.statusReports().size());
          }
        }
      }
    } catch (Exception e) {
      // fail-soft: keep the stale blob/source, log the failure
      log.error("mds.refresh.failed reason={}", e.getMessage(), e);
      throw new RuntimeException("MDS BLOB refresh failed: " + e.getMessage(), e);
    }
  }

  /** The current in-house trust anchor source, or null before the first successful refresh. */
  public MdsTrustAnchorSource currentTrustAnchorSource() {
    return trustAnchorSource.get();
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
