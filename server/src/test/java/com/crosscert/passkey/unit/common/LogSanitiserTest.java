package com.crosscert.passkey.unit.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.common.log.LogSanitiser;
import org.junit.jupiter.api.Test;

class LogSanitiserTest {

  @Test
  void forLog_strips_cr_and_lf() {
    assertThat(LogSanitiser.forLog("a\nb\rc")).isEqualTo("a_b_c");
  }

  @Test
  void forLog_returns_empty_for_null() {
    assertThat(LogSanitiser.forLog(null)).isEmpty();
  }

  @Test
  void forLog_truncates_at_1024_chars() {
    String oversize = "x".repeat(1100);
    String result = LogSanitiser.forLog(oversize);
    assertThat(result).hasSize(1025); // 1024 + ellipsis
    assertThat(result).endsWith("…");
  }

  @Test
  void maskEmail_preserves_domain_and_masks_local_part() {
    assertThat(LogSanitiser.maskEmail("alice@example.com")).isEqualTo("a***@example.com");
  }

  @Test
  void maskEmail_handles_short_local_part() {
    assertThat(LogSanitiser.maskEmail("a@example.com")).isEqualTo("***@example.com");
  }

  @Test
  void maskEmail_returns_dash_for_blank() {
    assertThat(LogSanitiser.maskEmail(null)).isEqualTo("-");
    assertThat(LogSanitiser.maskEmail("")).isEqualTo("-");
    assertThat(LogSanitiser.maskEmail("   ")).isEqualTo("-");
  }

  @Test
  void maskEmail_strips_cr_lf_defensively() {
    assertThat(LogSanitiser.maskEmail("alice\n@evil.com")).doesNotContain("\n");
  }

  @Test
  void maskPhone_keeps_country_prefix_and_last_four() {
    assertThat(LogSanitiser.maskPhone("+82-10-1234-5678")).isEqualTo("+821****5678");
    assertThat(LogSanitiser.maskPhone("01012345678")).isEqualTo("****5678");
  }

  @Test
  void maskPhone_dashes_short_inputs() {
    assertThat(LogSanitiser.maskPhone(null)).isEqualTo("-");
    assertThat(LogSanitiser.maskPhone("")).isEqualTo("-");
  }

  @Test
  void shortId_keeps_last_eight_chars() {
    assertThat(LogSanitiser.shortId("11111111-2222-3333-4444-555566667777")).isEqualTo("…66667777");
    assertThat(LogSanitiser.shortId("short")).isEqualTo("short");
    assertThat(LogSanitiser.shortId(null)).isEqualTo("-");
  }

  @Test
  void truncateUserAgent_bounds_long_strings() {
    String ua = "x".repeat(200);
    String result = LogSanitiser.truncateUserAgent(ua);
    assertThat(result).hasSize(129);
    assertThat(result).endsWith("…");
  }
}
