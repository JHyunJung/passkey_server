package com.crosscert.passkey.ratelimit;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.log.LogSanitiser;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.ToIntFunction;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies per-tenant + per-endpoint-class rate limits after tenant resolution. Stricter buckets for
 * {@code register}, {@code authenticate}, and {@code admin-login} (the latter keyed by source IP to
 * defeat password brute force); everything else falls back to a generic limit.
 *
 * <p>Each request classifies the URI exactly once into a {@link PathClass}, which then drives both
 * the limit and the bucket key.
 */
@Slf4j
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

  private final RateLimitProperties props;
  private final RateLimiter limiter;
  private final EnumMap<PathClass, AtomicLong> denyCounts = newDenyCounts();
  private final OffsetDateTime since = OffsetDateTime.now(ZoneOffset.UTC);

  private static EnumMap<PathClass, AtomicLong> newDenyCounts() {
    EnumMap<PathClass, AtomicLong> map = new EnumMap<>(PathClass.class);
    for (PathClass c : PathClass.values()) {
      map.put(c, new AtomicLong());
    }
    return map;
  }

  /** Read-only snapshot for diagnostic endpoints. */
  public Snapshot snapshot() {
    Map<String, Integer> limits =
        Map.of(
            "REGISTER", props.registrationPerMinute(),
            "AUTHENTICATE", props.authenticationPerMinute(),
            "ADMIN_LOGIN", props.adminLoginPerMinute(),
            "DEFAULT", props.defaultPerMinute(),
            "CREDENTIAL_AUTH_VERIFY", props.credentialAuthVerifyPerMinute());
    EnumMap<PathClass, Long> denyView = new EnumMap<>(PathClass.class);
    denyCounts.forEach((k, v) -> denyView.put(k, v.get()));
    return new Snapshot(props.enabled(), since, limits, denyView);
  }

  public record Snapshot(
      boolean enabled,
      OffsetDateTime since,
      Map<String, Integer> limits,
      EnumMap<PathClass, Long> denyCount) {}

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!props.enabled()) {
      return true;
    }
    String uri = request.getRequestURI();
    return uri.startsWith("/actuator") || uri.startsWith("/_diag");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    PathClass cls = PathClass.classify(req.getRequestURI());
    int limit = cls.limitLookup.applyAsInt(props);
    String bucket = bucketKey(req, cls);
    if (!limiter.tryAcquire(bucket, limit)) {
      denyCounts.get(cls).incrementAndGet();
      log.warn(
          "ratelimit.exceeded bucket={} limit={} path={} ip={}",
          bucket,
          limit,
          LogSanitiser.forLog(req.getRequestURI()),
          req.getRemoteAddr());
      throw new BusinessException(ErrorCode.RATE_LIMIT_EXCEEDED);
    }
    chain.doFilter(req, res);
  }

  private String bucketKey(HttpServletRequest req, PathClass cls) {
    if (cls == PathClass.ADMIN_LOGIN) {
      // Pre-auth path → key by client IP. Email-derived key requires reading the body which we
      // can't safely do here; IP bucket is sufficient for v1 brute-force defence. The IP itself is
      // sourced from RemoteIpValve when X-Forwarded-For is enabled (see application.yml).
      return "ip:" + req.getRemoteAddr() + ":admin-login";
    }
    String tenantSegment =
        TenantContextHolder.optional()
            .map(c -> c.tenantId().toString())
            .orElse("anon:" + req.getRemoteAddr());
    return tenantSegment + ":" + cls.bucketName;
  }

  /**
   * URI → bucket name + limit lookup. Classified once per request. The {@link ToIntFunction} field
   * is held as a stateless method reference; ErrorProne can't prove that generically, hence the
   * suppression.
   */
  @SuppressWarnings("ImmutableEnumChecker")
  public enum PathClass {
    REGISTER("register", RateLimitProperties::registrationPerMinute),
    CREDENTIAL_AUTH_VERIFY(
        "credential-auth-verify", RateLimitProperties::credentialAuthVerifyPerMinute),
    AUTHENTICATE("authenticate", RateLimitProperties::authenticationPerMinute),
    ADMIN_LOGIN("admin-login", RateLimitProperties::adminLoginPerMinute),
    DEFAULT("default", RateLimitProperties::defaultPerMinute);

    final String bucketName;
    final ToIntFunction<RateLimitProperties> limitLookup;

    PathClass(String bucketName, ToIntFunction<RateLimitProperties> limitLookup) {
      this.bucketName = bucketName;
      this.limitLookup = limitLookup;
    }

    static PathClass classify(String uri) {
      if (uri.startsWith("/api/v1/rp/passkeys/register")) {
        return REGISTER;
      }
      // The verify step is the costly half of an authentication ceremony (WebAuthn signature
      // verification + signature counter persist) and the only path that admits a credentialId
      // guess to enter the protocol — so it gets its own stricter bucket. Order matters: must
      // match before the generic /authenticate prefix below.
      if (uri.startsWith("/api/v1/rp/passkeys/authenticate/verify")) {
        return CREDENTIAL_AUTH_VERIFY;
      }
      if (uri.startsWith("/api/v1/rp/passkeys/authenticate")) {
        return AUTHENTICATE;
      }
      if (uri.startsWith("/api/v1/admin/auth/login")) {
        return ADMIN_LOGIN;
      }
      return DEFAULT;
    }
  }
}
