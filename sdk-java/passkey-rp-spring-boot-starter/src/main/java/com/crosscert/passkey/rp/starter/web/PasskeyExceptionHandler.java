package com.crosscert.passkey.rp.starter.web;

import com.crosscert.passkey.rp.dto.ApiResponse;
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
 *
 * <p>The response body is always the unified {@link ApiResponse} envelope — identical schema to the
 * success path — so a Client never has to special-case error parsing.
 */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 10)
public class PasskeyExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(PasskeyExceptionHandler.class);

  @ExceptionHandler(RefreshReuseDetectedException.class)
  public ResponseEntity<ApiResponse<Void>> handleReuse(RefreshReuseDetectedException ex) {
    log.error("refresh-reuse traceId={} message={}", ex.traceId(), ex.getMessage());
    HttpHeaders h = new HttpHeaders();
    h.add("Clear-Site-Data", "\"cookies\"");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(h).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(RefreshTokenRevokedException.class)
  public ResponseEntity<ApiResponse<Void>> handleRevoked(RefreshTokenRevokedException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(PasskeyAuthenticationException.class)
  public ResponseEntity<ApiResponse<Void>> handleAuth(PasskeyAuthenticationException ex) {
    HttpHeaders h = new HttpHeaders();
    h.add(
        "WWW-Authenticate",
        ex.expired() ? "Bearer error=\"token_expired\"" : "Bearer error=\"invalid_token\"");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(h).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(ChallengeExpiredException.class)
  public ResponseEntity<ApiResponse<Void>> handleChallenge(ChallengeExpiredException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(CounterRegressionException.class)
  public ResponseEntity<ApiResponse<Void>> handleCounter(CounterRegressionException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(CredentialRevokedException.class)
  public ResponseEntity<ApiResponse<Void>> handleCredRevoked(CredentialRevokedException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(AaguidRejectedException.class)
  public ResponseEntity<ApiResponse<Void>> handleAaguid(AaguidRejectedException ex) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(PasskeyRateLimitException.class)
  public ResponseEntity<ApiResponse<Void>> handleRate(PasskeyRateLimitException ex) {
    HttpHeaders h = new HttpHeaders();
    if (ex.retryAfter() != null) {
      h.add("Retry-After", Long.toString(ex.retryAfter().toSeconds()));
    }
    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
        .headers(h)
        .body(ApiResponse.error(ex));
  }

  @ExceptionHandler(PasskeyCeremonyException.class)
  public ResponseEntity<ApiResponse<Void>> handleCeremony(PasskeyCeremonyException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(PasskeyTransportException.class)
  public ResponseEntity<ApiResponse<Void>> handleTransport(PasskeyTransportException ex) {
    log.warn("passkey.transport.failed message={}", ex.getMessage());
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiResponse.error(ex));
  }

  @ExceptionHandler(PasskeyApiException.class)
  public ResponseEntity<ApiResponse<Void>> handleApi(PasskeyApiException ex) {
    int status = ex.httpStatus() > 0 ? ex.httpStatus() : 500;
    return ResponseEntity.status(status).body(ApiResponse.error(ex));
  }
}
