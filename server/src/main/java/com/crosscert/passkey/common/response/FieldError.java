package com.crosscert.passkey.common.response;

public record FieldError(String field, Object rejectedValue, String reason) {}
