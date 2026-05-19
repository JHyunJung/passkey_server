package com.crosscert.passkey.rp.starter.web;

import com.crosscert.passkey.rp.starter.PasskeyProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ensures every request has a {@code traceId} value in MDC and on the response. Honours an inbound
 * {@code X-Trace-Id} header so upstream traces propagate; otherwise generates one.
 */
public class PasskeyMdcFilter extends OncePerRequestFilter {

  private final String headerName;

  public PasskeyMdcFilter(PasskeyProperties props) {
    this.headerName = props.getObservability().getMdcTraceHeader();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String traceId = request.getHeader(headerName);
    if (traceId == null || traceId.isBlank()) {
      traceId = UUID.randomUUID().toString();
    }
    MDC.put("traceId", traceId);
    response.setHeader(headerName, traceId);
    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove("traceId");
    }
  }
}
