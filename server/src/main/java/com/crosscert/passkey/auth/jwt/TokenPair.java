package com.crosscert.passkey.auth.jwt;

public record TokenPair(String accessToken, String refreshToken, long accessExpiresIn) {}
