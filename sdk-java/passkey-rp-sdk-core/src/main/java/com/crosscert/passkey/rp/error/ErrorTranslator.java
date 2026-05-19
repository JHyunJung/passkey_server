package com.crosscert.passkey.rp.error;

import com.crosscert.passkey.rp.dto.ApiResponse;
import java.time.Duration;

/**
 * Translates a non-success {@link ApiResponse} envelope into the right SDK exception subclass.
 * Centralises the code → exception mapping so {@code DefaultPasskeyClient} stays mapping-free.
 */
public final class ErrorTranslator {

  private ErrorTranslator() {}

  public static PasskeyApiException translate(
      ApiResponse<?> envelope, int httpStatus, Duration retryAfter) {
    String rawCode = envelope.code();
    if (rawCode == null && envelope.error() != null) {
      rawCode = envelope.error().errorCode();
    }
    ErrorCode mapped = ErrorCode.fromCode(rawCode);
    String message = envelope.message();
    String traceId = envelope.traceId();

    return switch (mapped) {
      case EXPIRED_TOKEN, INVALID_TOKEN, INVALID_API_KEY, UNAUTHORIZED ->
          new PasskeyAuthenticationException(mapped, rawCode, httpStatus, message, traceId);
      case REFRESH_TOKEN_REVOKED ->
          new RefreshTokenRevokedException(rawCode, httpStatus, message, traceId);
      case REFRESH_TOKEN_REUSED ->
          new RefreshReuseDetectedException(rawCode, httpStatus, message, traceId);
      case CHALLENGE_NOT_FOUND ->
          new ChallengeExpiredException(rawCode, httpStatus, message, traceId);
      case SIGNATURE_COUNTER_REGRESSION ->
          new CounterRegressionException(rawCode, httpStatus, message, traceId);
      case CREDENTIAL_REVOKED ->
          new CredentialRevokedException(rawCode, httpStatus, message, traceId);
      case AAGUID_NOT_ALLOWED -> new AaguidRejectedException(rawCode, httpStatus, message, traceId);
      case RATE_LIMIT_EXCEEDED ->
          new PasskeyRateLimitException(rawCode, httpStatus, message, traceId, retryAfter);
      case ATTESTATION_INVALID,
              ASSERTION_INVALID,
              CREDENTIAL_NOT_FOUND,
              WEBAUTHN_CONFIG_NOT_FOUND,
              ORIGIN_NOT_ALLOWED,
              MDS_TRUST_FAILED,
              MDS_UNAVAILABLE,
              AUTHENTICATOR_REVOKED,
              SYNCABLE_NOT_ALLOWED ->
          new PasskeyCeremonyException(mapped, rawCode, httpStatus, message, traceId);
      default -> new PasskeyApiException(mapped, rawCode, httpStatus, message, traceId);
    };
  }
}
