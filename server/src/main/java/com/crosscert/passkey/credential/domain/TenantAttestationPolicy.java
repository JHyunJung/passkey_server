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
@Table(name = "tenant_attestation_policy")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TenantAttestationPolicy extends TenantScopedEntity {

  /**
   * All-zero AAGUID — reported by some legacy authenticators that decline to identify themselves.
   */
  private static final UUID ZERO_AAGUID = new UUID(0L, 0L);

  // "mode" is reserved in Oracle; we map to the more explicit `attestation_mode` column instead.
  @Enumerated(EnumType.STRING)
  @Column(name = "attestation_mode", nullable = false)
  private AttestationMode mode;

  /** CSV of AAGUIDs (string-form UUIDs). */
  @Column(name = "allowed_aaguids")
  private String allowedAaguids;

  @Column(name = "denied_aaguids")
  private String deniedAaguids;

  /**
   * When true, register flow uses the strict {@code WebAuthnManager} backed by FIDO MDS3 trust
   * anchors. Requires server-side {@code passkey.mds.enabled=true}; otherwise registration fails
   * with {@code MDS_UNAVAILABLE}.
   */
  // Oracle 19c lacks SQL BOOLEAN; pin to TINYINT so the schema validator accepts NUMBER(1).
  @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.TINYINT)
  @Column(name = "mds_strict", nullable = false)
  private boolean mdsStrict;

  /**
   * Explicit opt-in for null / all-zero AAGUID. Default false = strict. Without this flag, an
   * authenticator that omits its AAGUID (or reports zeros) is rejected in every mode — closing the
   * "null AAGUID bypasses DENYLIST/ANY" gap (P0-3).
   */
  @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.TINYINT)
  @Column(name = "allow_zero_aaguid", nullable = false)
  private boolean allowZeroAaguid;

  /**
   * Explicit opt-out for syncable / backup-eligible authenticators (P1-4). Default true preserves
   * existing behaviour — flip OFF for tenants whose compliance regime forbids cloud-synced passkeys
   * (e.g. iCloud Keychain, Google Password Manager). Enforced in {@code
   * RegistrationService.finishRegistration} via {@link #acceptsSyncable(boolean)}.
   */
  @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.TINYINT)
  @Column(name = "allow_syncable", nullable = false)
  private boolean allowSyncable;

  private TenantAttestationPolicy(
      UUID id,
      UUID tenantId,
      AttestationMode mode,
      String allowed,
      String denied,
      boolean mdsStrict,
      boolean allowZeroAaguid,
      boolean allowSyncable) {
    super(id, tenantId);
    this.mode = mode;
    this.allowedAaguids = allowed;
    this.deniedAaguids = denied;
    this.mdsStrict = mdsStrict;
    this.allowZeroAaguid = allowZeroAaguid;
    this.allowSyncable = allowSyncable;
  }

  public static TenantAttestationPolicy permissive(UUID tenantId) {
    return new TenantAttestationPolicy(
        UUID.randomUUID(), tenantId, AttestationMode.ANY, null, null, false, false, true);
  }

  public boolean accepts(UUID aaguid) {
    boolean isNullOrZero = aaguid == null || ZERO_AAGUID.equals(aaguid);
    if (isNullOrZero) {
      // Closes the legacy bypass — every mode requires explicit opt-in to accept null/zero.
      return allowZeroAaguid;
    }
    Set<UUID> allowed = parse(allowedAaguids);
    Set<UUID> denied = parse(deniedAaguids);
    return switch (mode) {
      case ANY -> true;
      case ALLOWLIST -> allowed.contains(aaguid);
      case DENYLIST -> !denied.contains(aaguid);
    };
  }

  /**
   * Whether the tenant accepts syncable / backup-eligible passkeys. Caller is the registration
   * service; combined with {@link #accepts(UUID)} for the AAGUID dimension.
   */
  public boolean acceptsSyncable(boolean credentialBackupEligible) {
    if (!credentialBackupEligible) {
      return true;
    }
    return allowSyncable;
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
      AttestationMode mode,
      java.util.List<String> allowed,
      java.util.List<String> denied,
      boolean mdsStrict,
      boolean allowZeroAaguid,
      boolean allowSyncable) {
    this.mode = mode;
    this.allowedAaguids = csvOrNull(allowed);
    this.deniedAaguids = csvOrNull(denied);
    this.mdsStrict = mdsStrict;
    this.allowZeroAaguid = allowZeroAaguid;
    this.allowSyncable = allowSyncable;
  }

  private static String csvOrNull(java.util.List<String> list) {
    if (list == null || list.isEmpty()) {
      return null;
    }
    return String.join(",", list);
  }
}
