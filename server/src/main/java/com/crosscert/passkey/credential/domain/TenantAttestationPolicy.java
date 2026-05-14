package com.crosscert.passkey.credential.domain;

import com.crosscert.passkey.infrastructure.jpa.TenantScopedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@Table(name = "tenant_attestation_policy", schema = "passkey")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TenantAttestationPolicy extends TenantScopedEntity {

  @Enumerated(EnumType.STRING)
  @Column(name = "mode", nullable = false)
  private AttestationMode mode;

  /** CSV of AAGUIDs (string-form UUIDs). */
  @Column(name = "allowed_aaguids")
  private String allowedAaguids;

  @Column(name = "denied_aaguids")
  private String deniedAaguids;

  private TenantAttestationPolicy(
      UUID id, UUID tenantId, AttestationMode mode, String allowed, String denied) {
    super(id, tenantId);
    this.mode = mode;
    this.allowedAaguids = allowed;
    this.deniedAaguids = denied;
  }

  public static TenantAttestationPolicy permissive(UUID tenantId) {
    return new TenantAttestationPolicy(
        UUID.randomUUID(), tenantId, AttestationMode.ANY, null, null);
  }

  public boolean accepts(UUID aaguid) {
    if (mode == AttestationMode.ANY || aaguid == null) {
      return mode != AttestationMode.ALLOWLIST;
    }
    Set<UUID> allowed = parse(allowedAaguids);
    Set<UUID> denied = parse(deniedAaguids);
    return switch (mode) {
      case ANY -> true;
      case ALLOWLIST -> allowed.contains(aaguid);
      case DENYLIST -> !denied.contains(aaguid);
    };
  }

  private Set<UUID> parse(String csv) {
    if (csv == null || csv.isBlank()) {
      return Set.of();
    }
    return Arrays.stream(csv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .map(UUID::fromString)
        .collect(Collectors.toUnmodifiableSet());
  }

  /** Mutates the policy in place (admin upsert). */
  public void update(
      AttestationMode mode, java.util.List<String> allowed, java.util.List<String> denied) {
    this.mode = mode;
    this.allowedAaguids = csvOrNull(allowed);
    this.deniedAaguids = csvOrNull(denied);
  }

  private static String csvOrNull(java.util.List<String> list) {
    if (list == null || list.isEmpty()) {
      return null;
    }
    return String.join(",", list);
  }
}
