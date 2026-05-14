package com.crosscert.passkey.common.response;

import com.crosscert.passkey.common.exception.ErrorCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.List;
import org.slf4j.MDC;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
    boolean success,
    String code,
    String message,
    T data,
    ErrorDetail error,
    String traceId,
    LocalDateTime timestamp) {

  public static <T> ApiResponse<T> ok(T data) {
    return new ApiResponse<>(
        true, "OK", "Success", data, null, MDC.get("traceId"), LocalDateTime.now());
  }

  public static <T> ApiResponse<T> ok(String message, T data) {
    return new ApiResponse<>(
        true, "OK", message, data, null, MDC.get("traceId"), LocalDateTime.now());
  }

  public static ApiResponse<Void> ok() {
    return new ApiResponse<>(
        true, "OK", "Success", null, null, MDC.get("traceId"), LocalDateTime.now());
  }

  public static ApiResponse<Void> error(ErrorCode code) {
    return new ApiResponse<>(
        false,
        code.getCode(),
        code.getMessage(),
        null,
        new ErrorDetail(code.getCode(), null),
        MDC.get("traceId"),
        LocalDateTime.now());
  }

  public static ApiResponse<Void> error(ErrorCode code, List<FieldError> fieldErrors) {
    return new ApiResponse<>(
        false,
        code.getCode(),
        code.getMessage(),
        null,
        new ErrorDetail(code.getCode(), fieldErrors),
        MDC.get("traceId"),
        LocalDateTime.now());
  }

  public static ApiResponse<Void> error(ErrorCode code, String detailMessage) {
    return new ApiResponse<>(
        false,
        code.getCode(),
        detailMessage,
        null,
        new ErrorDetail(code.getCode(), null),
        MDC.get("traceId"),
        LocalDateTime.now());
  }
}
