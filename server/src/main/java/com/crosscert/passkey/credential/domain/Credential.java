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
@Table(name = "credential", schema = "passkey")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Credential extends TenantScopedEntity {

  @Column(name = "tenant_user_id", nullable = false, updatable = false, columnDefinition = "uuid")
  private UUID tenantUserId;

  /** base64url-encoded raw credential id. */
  @Column(name = "credential_id", nullable = false, updatable = false)
  private String credentialId;

  @Column(name = "public_key_cose", nullable = false, updatable = false)
  private byte[] publicKeyCose;

  @Column(name = "aaguid", columnDefinition = "uuid")
  private UUID aaguid;

  /** CSV of transports. */
  @Column(name = "transports")
  private String transports;

  /** base64url-encoded user handle. */
  @Column(name = "user_handle", nullable = false, updatable = false)
  private String userHandle;

  @Column(name = "signature_counter", nullable = false)
  private long signatureCounter;

  @Column(name = "backup_eligible", nullable = false)
  private boolean backupEligible;

  @Column(name = "backup_state", nullable = false)
  private boolean backupState;

  @Column(name = "nickname")
  private String nickname;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false)
  private CredentialStatus status;

  @Column(name = "last_used_at")
  private OffsetDateTime lastUsedAt;

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

  public void revoke() {
    this.status = CredentialStatus.REVOKED;
  }

  public boolean isActive() {
    return this.status == CredentialStatus.ACTIVE;
  }

  /**
   * Updates the signature counter after a successful assertion. Throws {@code
   * SIGNATURE_COUNTER_REGRESSION} when {@code newCounter} is less than or equal to the stored
   * counter — this is the canonical clone-detection check from FIDO2.
   *
   * <p>Spec note: a {@code newCounter} of 0 means the authenticator does not implement signature
   * counters. In that case the stored counter is also 0 — we treat counter == 0 → no regression
   * possible.
   */
  public void updateSignatureCounter(long newCounter) {
    if (newCounter == 0 && this.signatureCounter == 0) {
      // Authenticator does not use a counter. Nothing to verify.
    } else if (newCounter <= this.signatureCounter) {
      throw new BusinessException(ErrorCode.SIGNATURE_COUNTER_REGRESSION);
    }
    this.signatureCounter = newCounter;
    this.lastUsedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }

  public void recordUse() {
    this.lastUsedAt = OffsetDateTime.now(ZoneOffset.UTC);
  }
}
