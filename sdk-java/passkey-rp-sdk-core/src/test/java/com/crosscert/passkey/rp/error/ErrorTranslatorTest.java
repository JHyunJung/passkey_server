package com.crosscert.passkey.rp.error;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.rp.dto.ApiResponse;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class ErrorTranslatorTest {

  @Test
  void maps_p002_to_challenge_expired() {
    ApiResponse<Object> env =
        new ApiResponse<>(false, "P002", "Challenge expired", null, null, "t-1", null);
    PasskeyApiException ex = ErrorTranslator.translate(env, 400, null);
    assertThat(ex).isInstanceOf(ChallengeExpiredException.class);
    assertThat(ex.errorCode()).isEqualTo(ErrorCode.CHALLENGE_NOT_FOUND);
    assertThat(ex.traceId()).isEqualTo("t-1");
  }

  @Test
  void maps_a012_to_refresh_reuse() {
    ApiResponse<Object> env =
        new ApiResponse<>(false, "A012", "Refresh reuse", null, null, "t-2", null);
    PasskeyApiException ex = ErrorTranslator.translate(env, 401, null);
    assertThat(ex).isInstanceOf(RefreshReuseDetectedException.class);
  }

  @Test
  void maps_r001_with_retry_after() {
    ApiResponse<Object> env =
        new ApiResponse<>(false, "R001", "Rate limited", null, null, "t-3", null);
    PasskeyRateLimitException ex =
        (PasskeyRateLimitException) ErrorTranslator.translate(env, 429, Duration.ofSeconds(7));
    assertThat(ex.retryAfter()).isEqualTo(Duration.ofSeconds(7));
  }

  @Test
  void maps_unknown_code_to_generic_api_exception() {
    ApiResponse<Object> env = new ApiResponse<>(false, "X999", "unknown", null, null, "t-4", null);
    PasskeyApiException ex = ErrorTranslator.translate(env, 500, null);
    assertThat(ex.errorCode()).isEqualTo(ErrorCode.UNKNOWN);
    assertThat(ex.getClass()).isEqualTo(PasskeyApiException.class);
  }
}
