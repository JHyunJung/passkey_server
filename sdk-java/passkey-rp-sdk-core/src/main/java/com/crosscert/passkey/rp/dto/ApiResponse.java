package com.crosscert.passkey.rp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.List;

/**
 * The server's response envelope. Every response from {@code /api/v1/rp/**} (and from the JWKS
 * endpoint when relayed by the SDK) is wrapped in this shape; the SDK unwraps it before returning
 * typed payloads to the caller.
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

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ErrorDetail(String errorCode, List<FieldError> fieldErrors) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record FieldError(String field, String message, String rejectedValue) {}
}
