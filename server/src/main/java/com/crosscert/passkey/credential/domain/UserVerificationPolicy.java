package com.crosscert.passkey.credential.domain;

/**
 * Tenant-level WebAuthn user verification policy. Maps onto the WebAuthn {@code
 * UserVerificationRequirement} dictionary, with one server-side enforcement decision baked in: only
 * {@link #REQUIRED} causes ceremony verification to fail-closed when the UV flag is not set on the
 * authenticator data.
 *
 * <ul>
 *   <li>{@code REQUIRED} — UV must be present; webauthn4j is configured with {@code
 *       userVerificationRequired=true}. Missing UV → ASSERTION_INVALID.
 *   <li>{@code PREFERRED} — Server still requests UV in the options payload, but does NOT
 *       fail-closed if the authenticator declines. Industry default for consumer flows.
 *   <li>{@code DISCOURAGED} — Server explicitly does not need UV; useful for legacy authenticators
 *       or shared-device flows. Same server-side enforcement as PREFERRED (best-effort).
 * </ul>
 */
public enum UserVerificationPolicy {
  REQUIRED,
  PREFERRED,
  DISCOURAGED;

  /**
   * Whether the server should fail-closed when the authenticator does not assert UV. Only {@code
   * REQUIRED} returns {@code true}; the other two are best-effort hints to the authenticator, never
   * strict server-side gates. Used by {@code RegistrationService} and {@code AuthenticationService}
   * when constructing webauthn4j parameters.
   */
  public boolean isStrictRequired() {
    return this == REQUIRED;
  }
}
