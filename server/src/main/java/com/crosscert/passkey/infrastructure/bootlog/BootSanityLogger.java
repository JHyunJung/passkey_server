package com.crosscert.passkey.infrastructure.bootlog;

import com.crosscert.passkey.auth.apikey.service.ApiKeyProperties;
import com.crosscert.passkey.auth.jwt.JwtProperties;
import com.crosscert.passkey.credential.metadata.MdsProperties;
import com.crosscert.passkey.ratelimit.RateLimitProperties;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Emits a single multi-line INFO block when the application is ready to serve traffic. The intent
 * is operational: during an incident the first thing on-call grabs is the boot log to verify which
 * profile is active, whether MDS is enabled, whether rate limiting is on, what JWT TTL is in
 * effect, and how cookies are configured. Having this in one place — keyed off {@code
 * passkey.boot.ready} — saves a round trip into config files.
 *
 * <p>Nothing sensitive is logged: secrets are reduced to their byte length, and the JWT issuer is a
 * non-secret identifier. If a value is wrong the dump itself often surfaces the misconfiguration.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BootSanityLogger {

  private final Environment env;
  private final RateLimitProperties rateLimit;
  private final ApiKeyProperties apiKey;
  private final JwtProperties jwt;
  private final MdsProperties mds;

  @EventListener(ApplicationReadyEvent.class)
  public void logBootSanity() {
    String profiles = String.join(",", Arrays.asList(env.getActiveProfiles()));
    if (profiles.isEmpty()) {
      profiles = "default";
    }
    boolean adminEnabled = Boolean.parseBoolean(env.getProperty("passkey.admin.enabled", "false"));
    boolean cookieSecure = Boolean.parseBoolean(env.getProperty("passkey.cookie.secure", "true"));
    String cookieSameSite = env.getProperty("passkey.cookie.same-site", "Lax");
    String adminOrigin = env.getProperty("passkey.admin.console-origin", "");

    log.info(
        "passkey.boot.ready profiles={} adminEnabled={} adminConsoleOrigin={} "
            + "cookie.secure={} cookie.sameSite={} "
            + "jwt.issuer={} jwt.accessTtlSec={} jwt.refreshTtlSec={} jwt.previousSecretSet={} "
            + "apikey.argon2Memory={}KB apikey.argon2Iter={} apikey.argon2Parallel={} "
            + "ratelimit.enabled={} ratelimit.register={}/min ratelimit.authenticate={}/min "
            + "ratelimit.credentialAuthVerify={}/min ratelimit.adminLogin={}/min "
            + "ratelimit.default={}/min "
            + "mds.enabled={} mds.refreshCron={} mds.allowNotFidoCertified={}",
        profiles,
        adminEnabled,
        adminOrigin.isBlank() ? "-" : adminOrigin,
        cookieSecure,
        cookieSameSite,
        jwt.issuer(),
        jwt.accessTtlSeconds(),
        jwt.refreshTtlSeconds(),
        jwt.previousSecret() != null && !jwt.previousSecret().isBlank(),
        apiKey.argon2MemoryKb(),
        apiKey.argon2Iterations(),
        apiKey.argon2Parallelism(),
        rateLimit.enabled(),
        rateLimit.registrationPerMinute(),
        rateLimit.authenticationPerMinute(),
        rateLimit.credentialAuthVerifyPerMinute(),
        rateLimit.adminLoginPerMinute(),
        rateLimit.defaultPerMinute(),
        mds.isEnabled(),
        mds.getRefreshCron(),
        mds.isAllowNotFidoCertified());

    // Loud WARN for known-risky combinations so the line stands out in scrollback.
    if (!cookieSecure && "Lax".equalsIgnoreCase(cookieSameSite)) {
      log.info("passkey.boot.cookie.note cookie.secure=false (expected for local HTTP profile)");
    }
    if (mds.isEnabled()
        && (mds.getRootCertificatePath() == null || mds.getRootCertificatePath().isBlank())) {
      log.warn(
          "passkey.boot.mds.misconfig mds.enabled=true but rootCertificatePath is empty — "
              + "BLOB verification will fail");
    }
    if (!rateLimit.enabled() && Arrays.asList(env.getActiveProfiles()).contains("prod")) {
      log.warn("passkey.boot.ratelimit.disabled profile=prod — abuse defence is OFF");
    }
  }
}
