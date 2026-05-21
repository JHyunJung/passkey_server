package com.crosscert.passkey.demo.web.error;

import com.crosscert.passkey.rp.dto.ApiResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps the demo RP server's own {@link DemoBusinessException} to the unified {@code ApiResponse}
 * error envelope — byte-for-byte the same schema the passkey platform and the SDK's ceremony
 * endpoints use, so a Client never special-cases error parsing by endpoint.
 *
 * <p>Ordered ahead of the SDK's {@code PasskeyExceptionHandler} ({@code LOWEST_PRECEDENCE - 10}) so
 * demo-domain exceptions are handled here; passkey-domain exceptions still fall through to the SDK
 * handler.
 */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 20)
public class DemoExceptionHandler {

  @ExceptionHandler(DemoBusinessException.class)
  public ResponseEntity<ApiResponse<Void>> handle(DemoBusinessException ex) {
    return ResponseEntity.status(ex.httpStatus())
        .body(ApiResponse.error(ex.errorCode().code(), ex.getMessage()));
  }
}
