package com.crosscert.passkey.rp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RefreshResult(String accessToken, String refreshToken, long accessExpiresIn) {}
