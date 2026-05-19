package com.crosscert.passkey.rp.error;

/** P007 — credential revoked (by user, admin, or system). */
public class CredentialRevokedException extends PasskeyCeremonyException {
  public CredentialRevokedException(
      String rawCode, int httpStatus, String message, String traceId) {
    super(ErrorCode.CREDENTIAL_REVOKED, rawCode, httpStatus, message, traceId);
  }
}
