package com.crosscert.passkey.demo.web.error;

/**
 * Error codes for the demo RP server's own (non-passkey) endpoints.
 *
 * <p>Mirrors the passkey platform's convention — a single-letter domain prefix plus a three-digit
 * number — so a Client sees one consistent code scheme whether the failure originated in the RP
 * backend or the passkey platform. {@code D} is the demo/RP-domain prefix; the platform's own codes
 * use {@code C/A/T/P/R/M}.
 */
public enum DemoErrorCode {
  /**
   * Authenticated principal is missing — the JWT filter did not inject a {@code PasskeyPrincipal}.
   */
  UNAUTHORIZED("D001", "Authentication required"),
  /** The {@code externalUserId} from the verified token has no matching user record. */
  USER_NOT_FOUND("D002", "User not found");

  private final String code;
  private final String message;

  DemoErrorCode(String code, String message) {
    this.code = code;
    this.message = message;
  }

  public String code() {
    return code;
  }

  public String message() {
    return message;
  }
}
