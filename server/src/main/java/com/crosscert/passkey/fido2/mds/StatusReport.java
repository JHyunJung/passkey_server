package com.crosscert.passkey.fido2.mds;

/**
 * FIDO MDS3 authenticator status (a subset of the FIDO Metadata Service {@code AuthenticatorStatus}
 * registry). {@link #isCritical()} marks the statuses that must block registration: a revoked or
 * compromised authenticator must never be trusted regardless of tenant policy.
 *
 * <p>Unknown status strings from the BLOB map to {@link #UNKNOWN}, which is non-critical — an
 * unrecognized status does not by itself block registration (the BLOB may add new informational
 * statuses over time).
 */
public enum StatusReport {
  FIDO_CERTIFIED(false),
  FIDO_CERTIFIED_L1(false),
  FIDO_CERTIFIED_L2(false),
  FIDO_CERTIFIED_L3(false),
  NOT_FIDO_CERTIFIED(false),
  UPDATE_AVAILABLE(false),
  SELF_ASSERTION_SUBMITTED(false),
  REVOKED(true),
  ATTESTATION_KEY_COMPROMISE(true),
  USER_VERIFICATION_BYPASS(true),
  USER_KEY_REMOTE_COMPROMISE(true),
  USER_KEY_PHYSICAL_COMPROMISE(true),
  UNKNOWN(false);

  private final boolean critical;

  StatusReport(boolean critical) {
    this.critical = critical;
  }

  /** Whether this status must block registration (revoked / compromised classes). */
  public boolean isCritical() {
    return critical;
  }

  /**
   * Map a FIDO MDS status string to a {@link StatusReport}; unrecognized strings become UNKNOWN.
   */
  public static StatusReport fromMdsString(String status) {
    if (status == null) {
      return UNKNOWN;
    }
    try {
      return valueOf(status.trim().toUpperCase(java.util.Locale.ROOT));
    } catch (IllegalArgumentException e) {
      return UNKNOWN;
    }
  }
}
