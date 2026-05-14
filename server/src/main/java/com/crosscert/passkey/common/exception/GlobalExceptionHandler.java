package com.crosscert.passkey.common.exception;

import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.FieldError;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(BusinessException.class)
  public ResponseEntity<ApiResponse<Void>> handleBusiness(
      BusinessException e, HttpServletRequest req) {
    ErrorCode code = e.getErrorCode();
    if (code.getStatus().is5xxServerError()) {
      log.error("[BusinessException] {} {} - {}", req.getMethod(), req.getRequestURI(), code, e);
    } else {
      log.warn(
          "[BusinessException] {} {} - {} - {}",
          req.getMethod(),
          req.getRequestURI(),
          code.getCode(),
          e.getMessage());
    }
    return ResponseEntity.status(code.getStatus()).body(ApiResponse.error(code, e.getMessage()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException e) {
    List<FieldError> errors =
        e.getBindingResult().getFieldErrors().stream()
            .map(fe -> new FieldError(fe.getField(), fe.getRejectedValue(), fe.getDefaultMessage()))
            .toList();
    log.warn("[Validation] {} field errors", errors.size());
    return ResponseEntity.badRequest().body(ApiResponse.error(ErrorCode.INVALID_INPUT, errors));
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<ApiResponse<Void>> handleMissingParam(
      MissingServletRequestParameterException e) {
    log.warn("[MissingParameter] {}", e.getMessage());
    return ResponseEntity.badRequest()
        .body(ApiResponse.error(ErrorCode.MISSING_PARAMETER, e.getMessage()));
  }

  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ApiResponse<Void>> handleTypeMismatch(
      MethodArgumentTypeMismatchException e) {
    log.warn("[TypeMismatch] {}", e.getMessage());
    return ResponseEntity.badRequest()
        .body(ApiResponse.error(ErrorCode.TYPE_MISMATCH, e.getMessage()));
  }

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ApiResponse<Void>> handleNotReadable(HttpMessageNotReadableException e) {
    log.warn("[NotReadable] {}", e.getMessage());
    return ResponseEntity.badRequest()
        .body(ApiResponse.error(ErrorCode.INVALID_INPUT, "Malformed JSON request"));
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ApiResponse<Void>> handleMethodNotAllowed(
      HttpRequestMethodNotSupportedException e) {
    log.warn("[MethodNotAllowed] {}", e.getMessage());
    return ResponseEntity.status(ErrorCode.METHOD_NOT_ALLOWED.getStatus())
        .body(ApiResponse.error(ErrorCode.METHOD_NOT_ALLOWED, e.getMessage()));
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ApiResponse<Void>> handleAccessDenied(AccessDeniedException e) {
    log.warn("[AccessDenied] {}", e.getMessage());
    return ResponseEntity.status(ErrorCode.ACCESS_DENIED.getStatus())
        .body(ApiResponse.error(ErrorCode.ACCESS_DENIED));
  }

  @ExceptionHandler(DataIntegrityViolationException.class)
  public ResponseEntity<ApiResponse<Void>> handleDataIntegrity(DataIntegrityViolationException e) {
    log.warn("[DataIntegrityViolation] {}", e.getMostSpecificCause().getMessage());
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(ApiResponse.error(ErrorCode.TENANT_SLUG_DUPLICATE, "Data integrity violation"));
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiResponse<Void>> handleUnexpected(Exception e, HttpServletRequest req) {
    log.error("[Unhandled] {} {}", req.getMethod(), req.getRequestURI(), e);
    ErrorCode code = ErrorCode.INTERNAL_SERVER_ERROR;
    return ResponseEntity.status(code.getStatus()).body(ApiResponse.error(code));
  }
}
