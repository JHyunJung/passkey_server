package com.crosscert.passkey.rp.jwt;

import com.crosscert.passkey.rp.client.PasskeyClient;
import com.crosscert.passkey.rp.dto.RefreshResult;
import com.crosscert.passkey.rp.error.RefreshReuseDetectedException;
import com.crosscert.passkey.rp.error.RefreshTokenRevokedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thin wrapper around {@link PasskeyClient#refresh}. Surface for RP code that wants distinct
 * branches for "renewable" (returns a fresh pair) and "force logout" (caught reuse).
 *
 * <p>Reuse detection is a high-signal event: the server has just burned the entire rotation family.
 * We log at ERROR so it appears in alerting; the starter advice then maps the exception to a 401 +
 * {@code Clear-Site-Data} response.
 */
public final class RefreshTokenManager {

  private static final Logger log = LoggerFactory.getLogger(RefreshTokenManager.class);

  private final PasskeyClient client;

  public RefreshTokenManager(PasskeyClient client) {
    this.client = client;
  }

  public RefreshResult refresh(String refreshToken, Object requestContext) {
    try {
      return client.refresh(refreshToken, requestContext);
    } catch (RefreshReuseDetectedException reuse) {
      log.error(
          "passkey.refresh.reuse_detected traceId={} message={}",
          reuse.traceId(),
          reuse.getMessage());
      throw reuse;
    } catch (RefreshTokenRevokedException revoked) {
      log.warn(
          "passkey.refresh.revoked traceId={} message={}", revoked.traceId(), revoked.getMessage());
      throw revoked;
    }
  }
}
