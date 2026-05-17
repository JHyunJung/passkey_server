package com.crosscert.passkey.credential.domain;

/**
 * WebAuthn {@code residentKey} requirement (W3C spec). Mapped 1:1 onto the registration options
 * sent to the browser. {@code REQUIRED} is needed for username-less / discoverable-credential
 * flows; {@code PREFERRED} is the safe default; {@code DISCOURAGED} prevents resident-credential
 * creation when the tenant only ever uses the user-supplied externalUserId path.
 */
public enum ResidentKeyPolicy {
  REQUIRED,
  PREFERRED,
  DISCOURAGED,
}
