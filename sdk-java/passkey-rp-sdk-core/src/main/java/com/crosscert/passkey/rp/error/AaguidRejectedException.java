package com.crosscert.passkey.rp.error;

/** P008 — AAGUID not in the tenant allowlist. UX: explain that the authenticator is unsupported. */
public class AaguidRejectedException extends PasskeyCeremonyException {
  public AaguidRejectedException(String rawCode, int httpStatus, String message, String traceId) {
    super(ErrorCode.AAGUID_NOT_ALLOWED, rawCode, httpStatus, message, traceId);
  }
}
