package com.crosscert.passkey.rp.error;

/**
 * Base class for every exception the SDK throws when the passkey server returns a non-2xx envelope.
 * Carries the parsed {@link ErrorCode}, the raw server message, the {@code traceId} (which
 * propagates back through Spring's {@code @RestControllerAdvice} so operators can pivot across
 * server and RP logs), and the HTTP status as observed.
 */
public class PasskeyApiException extends RuntimeException {

  private final ErrorCode errorCode;
  private final String rawCode;
  private final int httpStatus;
  private final String traceId;

  public PasskeyApiException(
      ErrorCode errorCode, String rawCode, int httpStatus, String message, String traceId) {
    super(buildMessage(rawCode, message, traceId));
    this.errorCode = errorCode;
    this.rawCode = rawCode;
    this.httpStatus = httpStatus;
    this.traceId = traceId;
  }

  public PasskeyApiException(
      ErrorCode errorCode,
      String rawCode,
      int httpStatus,
      String message,
      String traceId,
      Throwable cause) {
    super(buildMessage(rawCode, message, traceId), cause);
    this.errorCode = errorCode;
    this.rawCode = rawCode;
    this.httpStatus = httpStatus;
    this.traceId = traceId;
  }

  public ErrorCode errorCode() {
    return errorCode;
  }

  public String rawCode() {
    return rawCode;
  }

  public int httpStatus() {
    return httpStatus;
  }

  public String traceId() {
    return traceId;
  }

  private static String buildMessage(String code, String message, String traceId) {
    StringBuilder sb = new StringBuilder();
    if (code != null) sb.append('[').append(code).append("] ");
    if (message != null) sb.append(message);
    if (traceId != null) sb.append(" (traceId=").append(traceId).append(')');
    return sb.toString();
  }
}
