package com.crosscert.passkey.fido2;

/**
 * The single checked exception the {@code fido2} core throws when a registration or authentication
 * ceremony fails verification. It carries a {@link FailureReason} so the calling domain service can
 * log a precise cause and map to the right {@code ErrorCode} — the core itself never depends on the
 * application's {@code BusinessException} / {@code ErrorCode} types (enforced by ArchUnit).
 */
public class Fido2VerificationException extends Exception {

  /** The specific verification step that failed. */
  public enum FailureReason {
    MALFORMED_CBOR,
    MALFORMED_CLIENT_DATA,
    WRONG_CEREMONY_TYPE,
    CHALLENGE_MISMATCH,
    ORIGIN_MISMATCH,
    RPID_HASH_MISMATCH,
    UP_FLAG_MISSING,
    UV_FLAG_REQUIRED,
    NO_ATTESTED_CREDENTIAL,
    UNSUPPORTED_ALGORITHM,
    UNSUPPORTED_ATTESTATION_FORMAT,
    ATTESTATION_INVALID,
    SIGNATURE_INVALID,
    /** The attestation certificate chain does not validate to an MDS trust anchor. */
    TRUST_PATH_INVALID,
    /** No MDS metadata entry exists for the authenticator's AAGUID. */
    MDS_TRUST_FAILED,
    /** The authenticator is revoked or compromised per its MDS status report. */
    AUTHENTICATOR_REVOKED
  }

  private final FailureReason reason;

  public Fido2VerificationException(FailureReason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public FailureReason reason() {
    return reason;
  }
}
