package com.crosscert.passkey.credential.domain;

import com.crosscert.passkey.infrastructure.jpa.TenantScopedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "tenant_webauthn_config", schema = "passkey")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TenantWebauthnConfig extends TenantScopedEntity {

  @Column(name = "rp_id", nullable = false)
  private String rpId;

  @Column(name = "rp_name", nullable = false)
  private String rpName;

  /** CSV of allowed origins (e.g. "https://app.example.com,https://www.example.com"). */
  @Column(name = "origins", nullable = false)
  private String origins;

  @Column(name = "timeout_ms", nullable = false)
  private int timeoutMs;

  @Enumerated(EnumType.STRING)
  @Column(name = "user_verification", nullable = false)
  private UserVerificationPolicy userVerification;

  @Enumerated(EnumType.STRING)
  @Column(name = "attestation_conveyance", nullable = false)
  private AttestationConveyance attestationConveyance;

  private TenantWebauthnConfig(
      UUID id,
      UUID tenantId,
      String rpId,
      String rpName,
      String origins,
      int timeoutMs,
      UserVerificationPolicy userVerification,
      AttestationConveyance attestationConveyance) {
    super(id, tenantId);
    this.rpId = rpId;
    this.rpName = rpName;
    this.origins = origins;
    this.timeoutMs = timeoutMs;
    this.userVerification = userVerification;
    this.attestationConveyance = attestationConveyance;
  }

  public static TenantWebauthnConfig create(
      UUID tenantId, String rpId, String rpName, List<String> origins) {
    return new TenantWebauthnConfig(
        UUID.randomUUID(),
        tenantId,
        rpId,
        rpName,
        String.join(",", origins),
        60_000,
        UserVerificationPolicy.PREFERRED,
        AttestationConveyance.NONE);
  }

  public List<String> originList() {
    return Arrays.stream(this.origins.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
  }
}
