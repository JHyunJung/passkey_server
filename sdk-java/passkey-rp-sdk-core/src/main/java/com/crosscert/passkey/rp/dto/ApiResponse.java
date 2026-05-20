package com.crosscert.passkey.rp.dto;

import com.crosscert.passkey.rp.error.PasskeyApiException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.List;
import org.slf4j.MDC;

/**
 * Unified response envelope, byte-for-byte compatible with the passkey server's {@code
 * ApiResponse<T>} (see {@code spring-boot-api-response-template.md}).
 *
 * <p>Used in two directions:
 *
 * <ul>
 *   <li><b>inbound</b> — the SDK parses the passkey server's responses into this shape before
 *       unwrapping the inner {@code T} or translating an error;
 *   <li><b>outbound</b> — {@code PasskeyCeremonyController} wraps its results in this same shape so
 *       a Client (app/web) sees one consistent schema across the RP backend and the passkey
 *       platform.
 * </ul>
 *
 * <p>{@code @JsonInclude(NON_NULL)} keeps the payload clean — {@code data} is omitted on errors,
 * {@code error} is omitted on success.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record ApiResponse<T>(
    boolean success,
    String code,
    String message,
    T data,
    ErrorDetail error,
    String traceId,
    LocalDateTime timestamp) {

  @JsonInclude(JsonInclude.Include.NON_NULL)
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ErrorDetail(String errorCode, List<FieldError> fieldErrors) {}

  /** Field-level validation error. Field order matches the server's {@code FieldError} record. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record FieldError(String field, Object rejectedValue, String reason) {}

  /** Success envelope with a payload. {@code traceId} is pulled from MDC. */
  public static <T> ApiResponse<T> ok(T data) {
    return new ApiResponse<>(
        true, "OK", "Success", data, null, MDC.get("traceId"), LocalDateTime.now());
  }

  /** Success envelope with a custom message. */
  public static <T> ApiResponse<T> ok(String message, T data) {
    return new ApiResponse<>(
        true, "OK", message, data, null, MDC.get("traceId"), LocalDateTime.now());
  }

  /** Success envelope with no payload (204-style operations). */
  public static ApiResponse<Void> ok() {
    return new ApiResponse<>(
        true, "OK", "Success", null, null, MDC.get("traceId"), LocalDateTime.now());
  }

  /** Error envelope built from a translated SDK exception, preserving the server's code/traceId. */
  public static ApiResponse<Void> error(PasskeyApiException ex) {
    String code = ex.rawCode() == null ? "" : ex.rawCode();
    String traceId = ex.traceId() != null ? ex.traceId() : MDC.get("traceId");
    return new ApiResponse<>(
        false,
        code,
        ex.getMessage(),
        null,
        new ErrorDetail(code, null),
        traceId,
        LocalDateTime.now());
  }

  /** Error envelope with an explicit code/message — used when no exception is in hand. */
  public static ApiResponse<Void> error(String code, String message) {
    return new ApiResponse<>(
        false,
        code,
        message,
        null,
        new ErrorDetail(code, null),
        MDC.get("traceId"),
        LocalDateTime.now());
  }
}
