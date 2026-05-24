package com.crosscert.passkey.credential.domain;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.infrastructure.jpa.TenantScopedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "credential")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Credential extends TenantScopedEntity {

  @Column(name = "tenant_user_id", nullable = false, updatable = false)
  private UUID tenantUserId;

  /** base64url-encoded raw credential id. */
  @Column(name = "credential_id", nullable = false, updatable = false)
  private String credentialId;

  // COSE public-key blob can exceed the implicit RAW(255) Hibernate would otherwise expect on
  // Oracle. Pin to a LOB so the DDL/Validator agree on BLOB semantics.
  @jakarta.persistence.Lob
  @Column(name = "public_key_cose", nullable = false, updatable = false)
  private byte[] publicKeyCose;

  @Column(name = "aaguid")
  private UUID aaguid;

  /** CSV of transports. */
  @Column(name = "transports")
  private String transports;

  /** base64url-encoded user handle. */
  @Column(name = "user_handle", nullable = false, updatable = false)
  private String userHandle;

  @Column(name = "signature_counter", nullable = false)
  private long signatureCounter;

  // Oracle 19c lacks a SQL BOOLEAN type. Pin the JDBC type so Hibernate's schema validator does
  // not insist on Types#BOOLEAN against our NUMBER(1) DDL.
  @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.TINYINT)
  @Column(name = "backup_eligible", nullable = false)
  private boolean backupEligible;

  @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.TINYINT)
  @Column(name = "backup_state", nullable = false)
  private boolean backupState;

  @Column(name = "nickname")
  private String nickname;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false)
  private CredentialStatus status;

  @Column(name = "last_used_at")
  private OffsetDateTime lastUsedAt;

  @Column(name = "revoked_at")
  private OffsetDateTime revokedAt;

  @Enumerated(EnumType.STRING)
  @Column(name = "revoked_reason")
  private CredentialRevokedReason revokedReason;

  @Column(name = "suspended_at")
  private OffsetDateTime suspendedAt;

  @Column(name = "suspended_reason", length = 64)
  private String suspendedReason;

  @Column(name = "unsuspended_at")
  private OffsetDateTime unsuspendedAt;

  @Column(name = "unsuspended_by", length = 128)
  private String unsuspendedBy;

  @SuppressWarnings("checkstyle:ParameterNumber")
  private Credential(
      UUID id,
      UUID tenantId,
      UUID tenantUserId,
      String credentialId,
      byte[] publicKeyCose,
      UUID aaguid,
      String transports,
      String userHandle,
      long signatureCounter,
      boolean backupEligible,
      boolean backupState) {
    super(id, tenantId);
    this.tenantUserId = tenantUserId;
    this.credentialId = credentialId;
    this.publicKeyCose = publicKeyCose;
    this.aaguid = aaguid;
    this.transports = transports;
    this.userHandle = userHandle;
    this.signatureCounter = signatureCounter;
    this.backupEligible = backupEligible;
    this.backupState = backupState;
    this.status = CredentialStatus.ACTIVE;
  }

  public static Credential create(
      UUID tenantId,
      UUID tenantUserId,
      String credentialId,
      byte[] publicKeyCose,
      UUID aaguid,
      String transports,
      String userHandle,
      long signatureCounter,
      boolean backupEligible,
      boolean backupState) {
    return new Credential(
        UUID.randomUUID(),
        tenantId,
        tenantUserId,
        credentialId,
        publicKeyCose,
        aaguid,
        transports,
        userHandle,
        signatureCounter,
        backupEligible,
        backupState);
  }

  public void rename(String nickname) {
    this.nickname = nickname;
  }

  /**
   * Revoke without recording a reason — kept for backward compatibility. Defaults to {@code
   * ADMIN_FORCED}. Prefer {@link #revoke(CredentialRevokedReason)} which captures who/when/why.
   */
  public void revoke() {
    revoke(CredentialRevokedReason.ADMIN_FORCED);
  }

  /** Revoke with explicit reason — captures revoked_at + reason for forensics. */
  public void revoke(CredentialRevokedReason reason) {
    if (this.status == CredentialStatus.REVOKED) {
      return; // idempotent
    }
    this.status = CredentialStatus.REVOKED;
    this.revokedAt = OffsetDateTime.now(ZoneOffset.UTC);
    this.revokedReason = reason;
  }

  /**
   * Suspend (post-registration auto-block path — currently MDS critical AAGUID detection).
   * Idempotent: re-suspending preserves the original suspendedAt/Reason. Throws
   * CREDENTIAL_INVALID_STATE on REVOKED credential (revoked is terminal).
   */
  public void suspend(String reasonDetail) {
    if (this.status == CredentialStatus.SUSPENDED) {
      return; // idempotent — keep original metadata
    }
    if (this.status == CredentialStatus.REVOKED) {
      throw new BusinessException(
          ErrorCode.CREDENTIAL_INVALID_STATE, "cannot suspend a revoked credential");
    }
    this.status = CredentialStatus.SUSPENDED;
    this.suspendedAt = OffsetDateTime.now(ZoneOffset.UTC);
    this.suspendedReason = reasonDetail;
  }

  /**
   * Platform Operator manual unsuspend. Restores ACTIVE; preserves suspendedAt/Reason for
   * forensics; sets unsuspendedAt/By. No refresh token re-issue — user must complete a fresh
   * assertion to receive a new session.
   */
  public void unsuspend(String actorId) {
    if (this.status != CredentialStatus.SUSPENDED) {
      throw new BusinessException(
          ErrorCode.CREDENTIAL_INVALID_STATE, "credential is not suspended");
    }
    this.status = CredentialStatus.ACTIVE;
    this.unsuspendedAt = OffsetDateTime.now(ZoneOffset.UTC);
    this.unsuspendedBy = actorId;
  }

  public boolean isSuspended() {
    return this.status == CredentialStatus.SUSPENDED;
  }

  public boolean isActive() {
    return this.status == CredentialStatus.ACTIVE;
  }

  /**
   * Updates the signature counter after a successful assertion. Throws {@code
   * SIGNATURE_COUNTER_REGRESSION} on any of the FIDO2 clone-detection conditions:
   *
   * <ul>
   *   <li>{@code newCounter == stored} (counter did not advance — possible replay)
   *   <li>{@code newCounter < stored} (counter went backwards — classic clone signal)
   *   <li>{@code newCounter == 0 && stored > 0} (counter downgraded to zero — clone with reset
   *       firmware, or a malicious authenticator pretending not to support counters; treated as a
   *       clone signal even though some legitimate firmware-reset cases will trip it — see WebAuthn
   *       L3 §6.1.1)
   * </ul>
   *
   * <p>The benign no-op case is {@code newCounter == 0 && stored == 0}: the authenticator never
   * advertised a counter at registration and continues not to. Anything else is a regression.
   */
  public void updateSignatureCounter(long newCounter) {
    boolean bothZero = newCounter == 0 && this.signatureCounter == 0;
    if (bothZero) {
      // Authenticator does not use a counter. Nothing to advance, nothing to verify.
      this.lastUsedAt = OffsetDateTime.now(ZoneOffset.UTC);
      return;
    }
    // Distinguish the three regression sub-types so the caller can grade severity:
    //  • DOWNGRADE_TO_ZERO — strongest clone signal (or malicious authenticator)
    //  • REPLAY           — counter unchanged; possible relay / replay attack
    //  • BACKWARDS        — classic clone (legitimate keys never decrement)
    // All three share the same ErrorCode and trigger the same downstream auto-revoke; the reason
    // is carried in the exception detail so logs and audit payloads can record it.
    if (newCounter == 0 && this.signatureCounter > 0) {
      throw new BusinessException(
          ErrorCode.SIGNATURE_COUNTER_REGRESSION, RegressionReason.DOWNGRADE_TO_ZERO.name());
    }
    if (newCounter == this.signatureCounter) {
      throw new BusinessException(
          ErrorCode.SIGNATURE_COUNTER_REGRESSION, RegressionReason.REPLAY.name());
    }
    if (newCounter < this.signatureCounter) {
      throw new BusinessException(
          ErrorCode.SIGNATURE_COUNTER_REGRESSION, RegressionReason.BACKWARDS.name());
    }
    this.signatureCounter = newCounter;
    this.lastUsedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }

  /**
   * Sub-classification of a {@code SIGNATURE_COUNTER_REGRESSION}. Carried as the exception detail
   * string so callers (and downstream log/audit consumers) can grade severity without re-deriving
   * the comparison from raw counters.
   */
  public enum RegressionReason {
    /** stored &gt; 0 but new == 0. Strongest clone signal — also covers malicious downgrade. */
    DOWNGRADE_TO_ZERO,
    /** stored == new. Counter did not advance — possible replay / relay attack. */
    REPLAY,
    /** new &lt; stored (and new &gt; 0). Classic clone — counters never legitimately decrement. */
    BACKWARDS
  }

  public void recordUse() {
    this.lastUsedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }

  /**
   * Reconciles the stored {@code backupState} (CTAP 2.1 BS flag) with the value observed in this
   * authentication's authenticator data. Returns {@code true} if the flag changed — the caller uses
   * that signal to emit a {@code CREDENTIAL_BACKUP_STATE_CHANGED} audit row and log line.
   *
   * <p>Spec note: BE (Backup Eligibility) is fixed at credential creation and never updated here;
   * BS can flip every authentication as the user enables / disables iCloud Keychain or Google
   * Password Manager backup. Compliance-sensitive RPs (e.g. finance) rely on this signal to
   * downgrade or revoke trust on newly synced credentials.
   */
  public boolean updateBackupState(boolean newBackupState) {
    if (this.backupState == newBackupState) {
      return false;
    }
    this.backupState = newBackupState;
    return true;
  }
}
