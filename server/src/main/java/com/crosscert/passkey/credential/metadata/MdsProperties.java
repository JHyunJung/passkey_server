package com.crosscert.passkey.credential.metadata;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for FIDO MDS3 integration. When {@code enabled=false} (default), no MDS beans are
 * registered and strict tenants get {@code MDS_UNAVAILABLE} on registration.
 *
 * <p>{@code rootCertificatePath} points at the FIDO Alliance Global Root CA — required to verify
 * the signed JWT BLOB. Operators must obtain the PEM from FIDO Alliance and mount it (e.g. via
 * Kubernetes secret) at the configured path. Without it the BLOB cannot be trusted.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "passkey.mds")
public class MdsProperties {

  /** Master switch. When false, no MDS beans are wired and strict tenants will fail-closed. */
  private boolean enabled = false;

  /** MDS3 BLOB endpoint. FIDO Alliance default is https://mds3.fidoalliance.org/ */
  private String blobUrl = "https://mds3.fidoalliance.org/";

  /**
   * Filesystem path to the FIDO Alliance Global Root CA PEM. {@code file:} or {@code classpath:}
   * prefix supported via Spring ResourceLoader.
   */
  private String rootCertificatePath = "classpath:fido/Global_Sign_Root_CA.pem";

  /** Cron expression for daily refresh (server local time). Default: 04:00 every day. */
  private String refreshCron = "0 0 4 * * *";

  /**
   * Whether to allow authenticators whose entries lack the FIDO_CERTIFIED status report. Plan
   * decision: REVOKED/COMPROMISED 계열만 차단, 미인증은 통과 (WARN 로그).
   */
  private boolean allowNotFidoCertified = true;
}
