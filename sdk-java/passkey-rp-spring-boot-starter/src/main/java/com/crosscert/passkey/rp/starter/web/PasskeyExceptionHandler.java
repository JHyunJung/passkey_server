package com.crosscert.passkey.rp.starter.web;

import com.crosscert.passkey.rp.error.AaguidRejectedException;
import com.crosscert.passkey.rp.error.ChallengeExpiredException;
import com.crosscert.passkey.rp.error.CounterRegressionException;
import com.crosscert.passkey.rp.error.CredentialRevokedException;
import com.crosscert.passkey.rp.error.PasskeyApiException;
import com.crosscert.passkey.rp.error.PasskeyAuthenticationException;
import com.crosscert.passkey.rp.error.PasskeyCeremonyException;
import com.crosscert.passkey.rp.error.PasskeyRateLimitException;
import com.crosscert.passkey.rp.error.PasskeyTransportException;
import com.crosscert.passkey.rp.error.RefreshReuseDetectedException;
import com.crosscert.passkey.rp.error.RefreshTokenRevokedException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Default mapping from SDK exceptions to HTTP responses. Lower-precedence than anything the RP
 * declares so they can override individual handlers.
 */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 10)
public class PasskeyExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(PasskeyExceptionHandler.class);

  @ExceptionHandler(RefreshReuseDetectedException.class)
  public ResponseEntity<Map<String, Object>> handleReuse(RefreshReuseDetectedException ex) {
    log.error("refresh-reuse traceId={} message={}", ex.traceId(), ex.getMessage());
    HttpHeaders h = new HttpHeaders();
    h.add("Clear-Site-Data", "\"cookies\"");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(h).body(body(ex));
  }

  @ExceptionHandler(RefreshTokenRevokedException.class)
  public ResponseEntity<Map<String, Object>> handleRevoked(RefreshTokenRevokedException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body(ex));
  }

  @ExceptionHandler(PasskeyAuthenticationException.class)
  public ResponseEntity<Map<String, Object>> handleAuth(PasskeyAuthenticationException ex) {
    HttpHeaders h = new HttpHeaders();
    h.add(
        "WWW-Authenticate",
        ex.expired() ? "Bearer error=\"token_expired\"" : "Bearer error=\"invalid_token\"");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(h).body(body(ex));
  }

  @ExceptionHandler(ChallengeExpiredException.class)
  public ResponseEntity<Map<String, Object>> handleChallenge(ChallengeExpiredException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body(ex));
  }

  @ExceptionHandler(CounterRegressionException.class)
  public ResponseEntity<Map<String, Object>> handleCounter(CounterRegressionException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body(ex));
  }

  @ExceptionHandler(CredentialRevokedException.class)
  public ResponseEntity<Map<String, Object>> handleCredRevoked(CredentialRevokedException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body(ex));
  }

  @ExceptionHandler(AaguidRejectedException.class)
  public ResponseEntity<Map<String, Object>> handleAaguid(AaguidRejectedException ex) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body(ex));
  }

  @ExceptionHandler(PasskeyRateLimitException.class)
  public ResponseEntity<Map<String, Object>> handleRate(PasskeyRateLimitException ex) {
    HttpHeaders h = new HttpHeaders();
    if (ex.retryAfter() != null) {
      h.add("Retry-After", Long.toString(ex.retryAfter().toSeconds()));
    }
    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).headers(h).body(body(ex));
  }

  @ExceptionHandler(PasskeyCeremonyException.class)
  public ResponseEntity<Map<String, Object>> handleCeremony(PasskeyCeremonyException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body(ex));
  }

  @ExceptionHandler(PasskeyTransportException.class)
  public ResponseEntity<Map<String, Object>> handleTransport(PasskeyTransportException ex) {
    log.warn("passkey.transport.failed message={}", ex.getMessage());
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body(ex));
  }

  @ExceptionHandler(PasskeyApiException.class)
  public ResponseEntity<Map<String, Object>> handleApi(PasskeyApiException ex) {
    return ResponseEntity.status(ex.httpStatus() > 0 ? ex.httpStatus() : 500).body(body(ex));
  }

  private static Map<String, Object> body(PasskeyApiException ex) {
    return Map.of(
        "success",
        false,
        "code",
        ex.rawCode() == null ? "" : ex.rawCode(),
        "message",
        ex.getMessage() == null ? "" : ex.getMessage(),
        "traceId",
        ex.traceId() == null ? "" : ex.traceId());
  }
}
