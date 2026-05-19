package com.crosscert.passkey.rp.error;

/** P002 — challenge expired or already consumed. UX: prompt user to start a new ceremony. */
public class ChallengeExpiredException extends PasskeyCeremonyException {
  public ChallengeExpiredException(String rawCode, int httpStatus, String message, String traceId) {
    super(ErrorCode.CHALLENGE_NOT_FOUND, rawCode, httpStatus, message, traceId);
  }
}
