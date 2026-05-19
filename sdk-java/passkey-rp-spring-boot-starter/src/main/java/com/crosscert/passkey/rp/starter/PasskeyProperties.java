package com.crosscert.passkey.rp.starter;

import java.net.URI;
import java.time.Duration;
import java.util.UUID;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration surface exposed under the {@code passkey.rp} prefix. Every field has a sensible
 * default so a single-tenant RP can get away with setting just {@code base-url} + {@code api-key}.
 */
@ConfigurationProperties(prefix = "passkey.rp")
public class PasskeyProperties {

  /** Base URL of the passkey server (no trailing slash). */
  private URI baseUrl;

  /** API key for single-tenant deployments. Ignored when {@code multi-tenant.enabled=true}. */
  private String apiKey;

  /** Optional tenant UUID. When set, the JWT filter asserts the verified {@code tid} matches. */
  private UUID tenantId;

  private String issuer = "passkey-platform";

  /** JWKS endpoint URL. Defaults to {@code <base-url>/.well-known/jwks.json}. */
  private URI jwksUri;

  private Duration jwksCacheTtl = Duration.ofHours(1);

  private final Http http = new Http();
  private final Auth auth = new Auth();
  private final Ceremony ceremony = new Ceremony();
  private final MultiTenant multiTenant = new MultiTenant();
  private final Observability observability = new Observability();

  public URI getBaseUrl() {
    return baseUrl;
  }

  public void setBaseUrl(URI baseUrl) {
    this.baseUrl = baseUrl;
  }

  public String getApiKey() {
    return apiKey;
  }

  public void setApiKey(String apiKey) {
    this.apiKey = apiKey;
  }

  public UUID getTenantId() {
    return tenantId;
  }

  public void setTenantId(UUID tenantId) {
    this.tenantId = tenantId;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public URI getJwksUri() {
    return jwksUri;
  }

  public void setJwksUri(URI jwksUri) {
    this.jwksUri = jwksUri;
  }

  public Duration getJwksCacheTtl() {
    return jwksCacheTtl;
  }

  public void setJwksCacheTtl(Duration jwksCacheTtl) {
    this.jwksCacheTtl = jwksCacheTtl;
  }

  public Http getHttp() {
    return http;
  }

  public Auth getAuth() {
    return auth;
  }

  public Ceremony getCeremony() {
    return ceremony;
  }

  public MultiTenant getMultiTenant() {
    return multiTenant;
  }

  public Observability getObservability() {
    return observability;
  }

  /** Resolves the effective JWKS URI, defaulting from baseUrl if not explicitly set. */
  public URI effectiveJwksUri() {
    if (jwksUri != null) {
      return jwksUri;
    }
    if (baseUrl == null) {
      throw new IllegalStateException("passkey.rp.base-url or jwks-uri must be set");
    }
    String s = baseUrl.toString();
    if (s.endsWith("/")) {
      s = s.substring(0, s.length() - 1);
    }
    return URI.create(s + "/.well-known/jwks.json");
  }

  public static class Http {
    private Duration connectTimeout = Duration.ofSeconds(2);
    private Duration readTimeout = Duration.ofSeconds(10);
    private int maxRetries = 3;
    private Duration retryBaseBackoff = Duration.ofMillis(200);

    public Duration getConnectTimeout() {
      return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
      return readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
      this.readTimeout = readTimeout;
    }

    public int getMaxRetries() {
      return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
      this.maxRetries = maxRetries;
    }

    public Duration getRetryBaseBackoff() {
      return retryBaseBackoff;
    }

    public void setRetryBaseBackoff(Duration retryBaseBackoff) {
      this.retryBaseBackoff = retryBaseBackoff;
    }
  }

  public static class Auth {
    /** {@code jwt} (default) | {@code session} | {@code off}. */
    private Mode mode = Mode.JWT;

    private final Jwt jwt = new Jwt();
    private final Session session = new Session();

    public Mode getMode() {
      return mode;
    }

    public void setMode(Mode mode) {
      this.mode = mode;
    }

    public Jwt getJwt() {
      return jwt;
    }

    public Session getSession() {
      return session;
    }

    public enum Mode {
      JWT,
      SESSION,
      OFF
    }

    public static class Jwt {
      private Duration clockSkew = Duration.ofSeconds(60);
      private String headerName = "Authorization";

      public Duration getClockSkew() {
        return clockSkew;
      }

      public void setClockSkew(Duration clockSkew) {
        this.clockSkew = clockSkew;
      }

      public String getHeaderName() {
        return headerName;
      }

      public void setHeaderName(String headerName) {
        this.headerName = headerName;
      }
    }

    public static class Session {
      private String attributeName = "PASSKEY_USER";
      private boolean invalidateOnReuse = true;

      public String getAttributeName() {
        return attributeName;
      }

      public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
      }

      public boolean isInvalidateOnReuse() {
        return invalidateOnReuse;
      }

      public void setInvalidateOnReuse(boolean invalidateOnReuse) {
        this.invalidateOnReuse = invalidateOnReuse;
      }
    }
  }

  public static class Ceremony {
    private boolean controllerEnabled = true;
    private String pathPrefix = "/passkey";

    public boolean isControllerEnabled() {
      return controllerEnabled;
    }

    public void setControllerEnabled(boolean controllerEnabled) {
      this.controllerEnabled = controllerEnabled;
    }

    public String getPathPrefix() {
      return pathPrefix;
    }

    public void setPathPrefix(String pathPrefix) {
      this.pathPrefix = pathPrefix;
    }
  }

  public static class MultiTenant {
    private boolean enabled = false;
    private String resolverBean = "passkeyApiKeyResolver";

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public String getResolverBean() {
      return resolverBean;
    }

    public void setResolverBean(String resolverBean) {
      this.resolverBean = resolverBean;
    }
  }

  public static class Observability {
    private boolean metricsEnabled = true;
    private String mdcTraceHeader = "X-Trace-Id";

    public boolean isMetricsEnabled() {
      return metricsEnabled;
    }

    public void setMetricsEnabled(boolean metricsEnabled) {
      this.metricsEnabled = metricsEnabled;
    }

    public String getMdcTraceHeader() {
      return mdcTraceHeader;
    }

    public void setMdcTraceHeader(String mdcTraceHeader) {
      this.mdcTraceHeader = mdcTraceHeader;
    }
  }
}
