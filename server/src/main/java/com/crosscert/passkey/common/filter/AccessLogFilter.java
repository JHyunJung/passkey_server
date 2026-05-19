package com.crosscert.passkey.common.filter;

import com.crosscert.passkey.common.log.LogSanitiser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * One-line per-request access log. Emits after the downstream chain has produced a status code so
 * we capture both the route and the outcome. The log line carries traceId/tenantId/adminId/apiKeyId
 * via MDC (set by upstream filters), plus method, sanitised path, status, duration in milliseconds,
 * and the client IP.
 *
 * <p>This is the operator's eye chart — when "the API is slow" comes in, this is the first thing to
 * grep. We intentionally do NOT log this for {@code /actuator/**}, {@code /_diag/**}, and the
 * OpenAPI/Swagger paths: their volume drowns out the signal and they are already exercised by
 * probes/dashboards.
 *
 * <p>Level policy:
 *
 * <ul>
 *   <li>{@code 5xx} → WARN (real failure, page-worthy)
 *   <li>{@code 4xx} → INFO (client-side; useful for tracing but not actionable on its own)
 *   <li>{@code 2xx/3xx} → INFO
 *   <li>uncaught throwable from the chain → ERROR (rare; the chain usually converts these)
 * </ul>
 */
public class AccessLogFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger("access");

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String uri = request.getRequestURI();
    return uri.startsWith("/actuator")
        || uri.startsWith("/_diag")
        || uri.startsWith("/swagger-ui")
        || uri.startsWith("/v3/api-docs");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    long startNanos = System.nanoTime();
    Throwable failure = null;
    try {
      chain.doFilter(req, res);
    } catch (IOException | ServletException | RuntimeException ex) {
      failure = ex;
      throw ex;
    } finally {
      long durationMs = (System.nanoTime() - startNanos) / 1_000_000L;
      int status = res.getStatus();
      // Pull MDC values here rather than from request attributes — downstream filters populate
      // tenantId/apiKeyId/adminId only after their own setup runs.
      String tenantId = nz(MDC.get("tenantId"));
      String apiKeyId = nz(MDC.get("apiKeyId"));
      String adminId = nz(MDC.get("adminId"));
      String method = req.getMethod();
      String path = LogSanitiser.forLog(req.getRequestURI());
      String ip = req.getRemoteAddr();

      if (failure != null) {
        log.error(
            "http method={} path={} status={} durationMs={} tenantId={} apiKeyId={} adminId={} "
                + "ip={} error={}",
            method,
            path,
            status,
            durationMs,
            tenantId,
            apiKeyId,
            adminId,
            ip,
            failure.getClass().getSimpleName());
      } else if (status >= 500) {
        log.warn(
            "http method={} path={} status={} durationMs={} tenantId={} apiKeyId={} adminId={} "
                + "ip={}",
            method,
            path,
            status,
            durationMs,
            tenantId,
            apiKeyId,
            adminId,
            ip);
      } else {
        log.info(
            "http method={} path={} status={} durationMs={} tenantId={} apiKeyId={} adminId={} "
                + "ip={}",
            method,
            path,
            status,
            durationMs,
            tenantId,
            apiKeyId,
            adminId,
            ip);
      }
    }
  }

  private static String nz(String s) {
    return s == null ? "-" : s;
  }
}
