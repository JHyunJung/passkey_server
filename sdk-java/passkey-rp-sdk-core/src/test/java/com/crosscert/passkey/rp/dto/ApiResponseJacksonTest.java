package com.crosscert.passkey.rp.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

/** Envelope parses with success + data + traceId, and tolerates unknown fields. */
class ApiResponseJacksonTest {

  private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

  @Test
  void parses_success_envelope_with_data_and_traceid() throws Exception {
    String json =
        """
        {"success":true,"code":"OK","message":"Success",
         "data":{"credentialDbId":"00000000-0000-0000-0000-000000000001",
                 "credentialId":"abc","aaguid":"00000000-0000-0000-0000-000000000000"},
         "traceId":"t-1","timestamp":"2026-05-19T10:00:00",
         "extra_future_field":42}
        """;
    ApiResponse<RegistrationResult> env =
        mapper.readValue(
            json,
            mapper
                .getTypeFactory()
                .constructParametricType(ApiResponse.class, RegistrationResult.class));
    assertThat(env.success()).isTrue();
    assertThat(env.code()).isEqualTo("OK");
    assertThat(env.traceId()).isEqualTo("t-1");
    assertThat(env.data().credentialId()).isEqualTo("abc");
  }

  @Test
  void parses_error_envelope() throws Exception {
    String json =
        """
        {"success":false,"code":"P002","message":"Challenge expired",
         "error":{"errorCode":"P002","fieldErrors":[]},
         "traceId":"t-2","timestamp":"2026-05-19T10:00:00"}
        """;
    ApiResponse<Object> env =
        mapper.readValue(
            json, mapper.getTypeFactory().constructParametricType(ApiResponse.class, Object.class));
    assertThat(env.success()).isFalse();
    assertThat(env.code()).isEqualTo("P002");
    assertThat(env.error().errorCode()).isEqualTo("P002");
  }
}
