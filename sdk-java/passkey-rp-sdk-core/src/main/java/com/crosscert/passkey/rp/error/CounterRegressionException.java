package com.crosscert.passkey.rp.error;

/** P005 — signature counter regression. The server has already revoked the credential. */
public class CounterRegressionException extends PasskeyCeremonyException {
  public CounterRegressionException(
      String rawCode, int httpStatus, String message, String traceId) {
    super(ErrorCode.SIGNATURE_COUNTER_REGRESSION, rawCode, httpStatus, message, traceId);
  }
}
