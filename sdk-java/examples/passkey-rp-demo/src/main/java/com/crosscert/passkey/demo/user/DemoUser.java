package com.crosscert.passkey.demo.user;

/**
 * A demo user account. {@code externalUserId} is the stable identifier the RP hands to the passkey
 * platform — the platform never sees the display name or any other RP-owned profile data.
 */
public record DemoUser(String externalUserId, String displayName) {}
