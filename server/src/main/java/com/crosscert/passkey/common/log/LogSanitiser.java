package com.crosscert.passkey.common.log;

/**
 * Centralised helpers for logging user-controlled strings without enabling log forging or PII
 * leaks.
 *
 * <ul>
 *   <li>{@link #forLog(String)} strips CR/LF so attacker-controlled input cannot inject fake log
 *       lines, and truncates excessively long values that would bloat log storage.
 *   <li>{@link #maskEmail(String)} keeps the domain visible (useful for grouping by tenant/RP) but
 *       masks the local-part.
 *   <li>{@link #maskPhone(String)} keeps the country prefix + last 4 digits.
 *   <li>{@link #shortId(String)} keeps only the last 8 chars of a UUID-shaped identifier.
 *   <li>{@link #truncateUserAgent(String)} bounds User-Agent to 128 chars for forensic logs.
 * </ul>
 */
public final class LogSanitiser {

  private static final int MAX_LEN = 1024;
  private static final int USER_AGENT_MAX = 128;
  private static final int SHORT_ID_TAIL = 8;

  private LogSanitiser() {}

  /** Returns the input with CR/LF replaced by {@code _} and truncated to 1024 chars. */
  public static String forLog(String s) {
    if (s == null) {
      return "";
    }
    String cleaned = s.replace('\n', '_').replace('\r', '_');
    return cleaned.length() > MAX_LEN ? cleaned.substring(0, MAX_LEN) + "…" : cleaned;
  }

  /**
   * Masks the local-part of an email — keeps domain visible for log grouping but does not expose
   * full PII. Strips CR/LF defensively in case the caller passes raw header values.
   */
  public static String maskEmail(String email) {
    if (email == null || email.isBlank()) {
      return "-";
    }
    String stripped = email.replace('\n', '_').replace('\r', '_');
    int at = stripped.indexOf('@');
    if (at <= 1) {
      return "***" + stripped.substring(Math.max(0, at));
    }
    return stripped.charAt(0) + "***" + stripped.substring(at);
  }

  /**
   * Masks a phone number — keeps optional {@code +CC} country code and the last 4 digits, replaces
   * the middle with stars. Anything that doesn't look like a phone is passed through {@link
   * #forLog(String)} so callers can use this on best-effort fields.
   */
  public static String maskPhone(String phone) {
    if (phone == null || phone.isBlank()) {
      return "-";
    }
    String digits = phone.replaceAll("[^0-9+]", "");
    if (digits.length() < 6) {
      return forLog(phone);
    }
    int tail = Math.min(4, digits.length());
    String last = digits.substring(digits.length() - tail);
    String prefix = digits.startsWith("+") ? digits.substring(0, Math.min(4, digits.length())) : "";
    return prefix + "****" + last;
  }

  /**
   * Last-8 abbreviation for UUID-shaped identifiers used in logs. Matches the {@code lastN} client
   * helper so server + admin SPA forensics line up.
   */
  public static String shortId(String id) {
    if (id == null || id.isBlank()) {
      return "-";
    }
    String stripped = id.replace('\n', '_').replace('\r', '_');
    return stripped.length() <= SHORT_ID_TAIL
        ? stripped
        : "…" + stripped.substring(stripped.length() - SHORT_ID_TAIL);
  }

  /**
   * Truncates a User-Agent header for forensic logs — full UA strings are noisy and often contain
   * fingerprintable data we don't want piling up unbounded in audit lines.
   */
  public static String truncateUserAgent(String userAgent) {
    if (userAgent == null || userAgent.isBlank()) {
      return "-";
    }
    String stripped = userAgent.replace('\n', '_').replace('\r', '_');
    return stripped.length() > USER_AGENT_MAX
        ? stripped.substring(0, USER_AGENT_MAX) + "…"
        : stripped;
  }
}
