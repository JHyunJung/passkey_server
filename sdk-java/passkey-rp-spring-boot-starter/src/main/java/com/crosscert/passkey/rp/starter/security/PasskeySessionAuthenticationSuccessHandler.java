package com.crosscert.passkey.rp.starter.security;

import com.crosscert.passkey.rp.dto.AuthenticationResult;
import com.crosscert.passkey.rp.starter.PasskeyProperties;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Drops a {@link PasskeyPrincipal} into the HTTP session under the configured attribute name.
 * Called by {@link com.crosscert.passkey.rp.starter.web.PasskeyCeremonyController} after a
 * successful {@code finish-authentication} call when {@code passkey.rp.auth.mode=session}.
 */
public class PasskeySessionAuthenticationSuccessHandler {

  private final PasskeyProperties props;

  public PasskeySessionAuthenticationSuccessHandler(PasskeyProperties props) {
    this.props = props;
  }

  public void onSuccess(HttpServletRequest request, AuthenticationResult result) {
    if (props.getAuth().getMode() != PasskeyProperties.Auth.Mode.SESSION) {
      return;
    }
    PasskeyPrincipal principal =
        new PasskeyPrincipal(
            props.getTenantId(), // single-tenant; multi-tenant flow injects upstream
            result.tenantUserId(),
            null,
            null);
    request
        .getSession(true)
        .setAttribute(props.getAuth().getSession().getAttributeName(), principal);
  }
}
