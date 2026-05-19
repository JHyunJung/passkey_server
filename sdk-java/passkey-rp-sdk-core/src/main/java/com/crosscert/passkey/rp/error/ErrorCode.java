package com.crosscert.passkey.rp.error;

/**
 * Mirror of the server's {@code ErrorCode} enum. Only the codes that an RP-facing endpoint can
 * return are listed — admin/internal codes are intentionally omitted so consumers don't reach for
 * them.
 *
 * <p>The {@code code} string is the wire format; SDK exception subclasses set the right code on
 * their {@code errorCode} field automatically. To translate a raw response envelope, use {@link
 * #fromCode(String)}.
 */
public enum ErrorCode {
  // Common
  INVALID_INPUT("C001", 400),
  METHOD_NOT_ALLOWED("C002", 405),
  ENTITY_NOT_FOUND("C003", 404),
  MISSING_PARAMETER("C004", 400),
  TYPE_MISMATCH("C005", 400),
  INTERNAL_SERVER_ERROR("C999", 500),

  // Auth
  UNAUTHORIZED("A001", 401),
  ACCESS_DENIED("A002", 403),
  EXPIRED_TOKEN("A003", 401),
  INVALID_TOKEN("A004", 401),
  INVALID_API_KEY("A005", 401),
  REFRESH_TOKEN_REVOKED("A011", 401),
  REFRESH_TOKEN_REUSED("A012", 401),

  // Tenant
  TENANT_NOT_FOUND("T001", 404),
  TENANT_INACTIVE("T002", 403),
  TENANT_CONTEXT_MISSING("T003", 400),

  // Passkey / WebAuthn
  WEBAUTHN_CONFIG_NOT_FOUND("P001", 404),
  CHALLENGE_NOT_FOUND("P002", 400),
  ATTESTATION_INVALID("P003", 400),
  ASSERTION_INVALID("P004", 400),
  SIGNATURE_COUNTER_REGRESSION("P005", 401),
  CREDENTIAL_NOT_FOUND("P006", 404),
  CREDENTIAL_REVOKED("P007", 401),
  AAGUID_NOT_ALLOWED("P008", 403),
  ORIGIN_NOT_ALLOWED("P009", 400),
  MDS_TRUST_FAILED("P010", 403),
  MDS_UNAVAILABLE("P011", 503),
  AUTHENTICATOR_REVOKED("P012", 403),
  SYNCABLE_NOT_ALLOWED("P013", 403),

  // Rate limit
  RATE_LIMIT_EXCEEDED("R001", 429),

  // Unknown — used when the server returns a code we don't model. Lets the SDK still surface the
  // raw envelope without crashing on enum lookup.
  UNKNOWN("", -1);

  private final String code;
  private final int httpStatus;

  ErrorCode(String code, int httpStatus) {
    this.code = code;
    this.httpStatus = httpStatus;
  }

  public String code() {
    return code;
  }

  public int httpStatus() {
    return httpStatus;
  }

  public static ErrorCode fromCode(String code) {
    if (code == null) {
      return UNKNOWN;
    }
    for (ErrorCode ec : values()) {
      if (ec.code.equals(code)) {
        return ec;
      }
    }
    return UNKNOWN;
  }
}
