package com.crosscert.passkey.demo.web.error;

/**
 * Business exception for the demo RP server's own endpoints. Carries a {@link DemoErrorCode} and
 * the HTTP status the {@link DemoExceptionHandler} should respond with — the handler converts it
 * into the unified {@code ApiResponse} error envelope.
 */
public class DemoBusinessException extends RuntimeException {

  private final DemoErrorCode errorCode;
  private final int httpStatus;

  public DemoBusinessException(DemoErrorCode errorCode, int httpStatus) {
    super(errorCode.message());
    this.errorCode = errorCode;
    this.httpStatus = httpStatus;
  }

  public DemoErrorCode errorCode() {
    return errorCode;
  }

  public int httpStatus() {
    return httpStatus;
  }

  /** 401 — the request lacks a usable authenticated principal. */
  public static DemoBusinessException unauthorized() {
    return new DemoBusinessException(DemoErrorCode.UNAUTHORIZED, 401);
  }

  /** 404 — the authenticated user has no record in the store. */
  public static DemoBusinessException userNotFound() {
    return new DemoBusinessException(DemoErrorCode.USER_NOT_FOUND, 404);
  }
}
