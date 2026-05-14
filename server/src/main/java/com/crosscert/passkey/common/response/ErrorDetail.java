package com.crosscert.passkey.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorDetail(String errorCode, List<FieldError> fieldErrors) {}
