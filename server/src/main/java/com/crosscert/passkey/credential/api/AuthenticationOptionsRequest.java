package com.crosscert.passkey.credential.api;

/** Optional externalUserId to scope allowCredentials. Empty means discoverable credential flow. */
public record AuthenticationOptionsRequest(String externalUserId) {}
