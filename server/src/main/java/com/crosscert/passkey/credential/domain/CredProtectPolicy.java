package com.crosscert.passkey.credential.domain;

/**
 * WebAuthn {@code credProtect} CTAP2 extension policy. Mapped to the integer levels in the spec:
 *
 * <ul>
 *   <li>{@link #NONE} — extension not sent. Legacy behaviour.
 *   <li>{@link #UV_OPTIONAL} — level 1. Discoverability allowed without UV.
 *   <li>{@link #UV_OPTIONAL_WITH_CREDID} — level 2. Discoverability requires UV, but lookup by
 *       credentialId still works without it.
 *   <li>{@link #UV_REQUIRED} — level 3. Every read requires user verification (recommended for
 *       financial / public-sector deployments).
 * </ul>
 */
public enum CredProtectPolicy {
  NONE(null),
  UV_OPTIONAL("userVerificationOptional"),
  UV_OPTIONAL_WITH_CREDID("userVerificationOptionalWithCredentialIDList"),
  UV_REQUIRED("userVerificationRequired");

  private final String extensionValue;

  CredProtectPolicy(String extensionValue) {
    this.extensionValue = extensionValue;
  }

  /** WebAuthn-spec string value for the {@code credentialProtectionPolicy} extension input. */
  public String extensionValue() {
    return extensionValue;
  }
}
