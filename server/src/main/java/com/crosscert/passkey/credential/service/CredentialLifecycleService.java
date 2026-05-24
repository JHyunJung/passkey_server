package com.crosscert.passkey.credential.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import com.crosscert.passkey.auth.jwt.repository.RefreshTokenRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialRevokedReason;
import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.credential.repository.TenantAttestationPolicyRepository;
import com.crosscert.passkey.credential.repository.TenantWebauthnConfigRepository;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialLifecycleService {

  private final CredentialRepository credentialRepo;
  private final TenantUserRepository tenantUserRepo;
  private final TenantWebauthnConfigRepository webauthnConfigRepo;
  private final TenantAttestationPolicyRepository attestationPolicyRepo;
  private final AuditService auditService;
  private final RefreshTokenRepository refreshTokenRepo;
  private final com.crosscert.passkey.credential.metrics.CeremonyMetrics metrics;

  @Transactional(readOnly = true)
  public List<CredentialView> listForUser(String externalUserId) {
    TenantUser user =
        tenantUserRepo
            .findByExternalId(externalUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    return credentialRepo.findAllByTenantUserId(user.getId()).stream()
        .map(CredentialView::from)
        .toList();
  }

  @Transactional
  public CredentialView rename(UUID credentialId, String nickname) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    c.rename(nickname);
    auditService.append(
        AuditEventType.CREDENTIAL_RENAMED,
        ActorType.END_USER,
        c.getTenantUserId().toString(),
        "CREDENTIAL",
        c.getId().toString(),
        Map.of("nickname", nickname == null ? "" : nickname));
    log.info(
        "credential.rename tenantId={} tenantUserId={} credentialDbId={}",
        c.getTenantId(),
        c.getTenantUserId(),
        c.getId());
    return CredentialView.from(c);
  }

  /**
   * RP-facing rename: enforces that {@code credentialId} actually belongs to the user identified by
   * {@code externalUserId}. The RP backend has only been authenticated as a tenant (via X-API-Key);
   * end-user ownership must be re-checked here or a malicious or buggy caller could mutate another
   * user's credential within the same tenant (IDOR).
   *
   * <p>On mismatch we return {@code CREDENTIAL_NOT_FOUND} rather than a distinct "ownership" code:
   * leaking the existence of someone else's credential by responding with a different status would
   * defeat the purpose of the check.
   */
  @Transactional
  public CredentialView renameForUser(UUID credentialId, String externalUserId, String nickname) {
    Credential c = lookupOwnedBy(credentialId, externalUserId);
    c.rename(nickname);
    auditService.append(
        AuditEventType.CREDENTIAL_RENAMED,
        ActorType.END_USER,
        c.getTenantUserId().toString(),
        "CREDENTIAL",
        c.getId().toString(),
        Map.of("nickname", nickname == null ? "" : nickname));
    log.info(
        "credential.rename.rp tenantId={} tenantUserId={} credentialDbId={}",
        c.getTenantId(),
        c.getTenantUserId(),
        c.getId());
    return CredentialView.from(c);
  }

  /**
   * Cross-tenant reassignment (P3 — rare). Requires source/target tenants to share the same {@code
   * rpId}: otherwise the moved credential would fail every WebAuthn ceremony post-move and
   * effectively be deadweight in the target tenant. Caller (admin controller) restricts to
   * PLATFORM_OPERATOR. Audit row is written on both sides under the new tenant context so the
   * target tenant's chain captures the import event.
   */
  @Transactional
  public CredentialView reassign(
      UUID credentialId, UUID sourceTenantId, UUID targetTenantId, UUID targetTenantUserId) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    if (!c.getTenantId().equals(sourceTenantId)) {
      throw new BusinessException(
          ErrorCode.ENTITY_NOT_FOUND, "credential is not under the requested source tenant");
    }
    if (sourceTenantId.equals(targetTenantId)) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "source and target tenants are identical");
    }
    TenantWebauthnConfig srcCfg =
        webauthnConfigRepo
            .findByTenantId(sourceTenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.WEBAUTHN_CONFIG_NOT_FOUND));
    TenantWebauthnConfig dstCfg =
        webauthnConfigRepo
            .findByTenantId(targetTenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.WEBAUTHN_CONFIG_NOT_FOUND));
    if (!srcCfg.getRpId().equals(dstCfg.getRpId())) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "rpId mismatch: " + srcCfg.getRpId() + " → " + dstCfg.getRpId());
    }
    TenantUser targetUser =
        tenantUserRepo
            .findById(targetTenantUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    if (!targetUser.getTenantId().equals(targetTenantId)) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT, "targetTenantUserId does not belong to targetTenant");
    }
    PolicyCompat compat = comparePolicies(c, srcCfg, dstCfg, sourceTenantId, targetTenantId);
    if (!compat.compatible()) {
      throw new BusinessException(
          ErrorCode.INVALID_INPUT,
          "policy incompatibility blocks reassign: " + String.join("; ", compat.blockers()));
    }

    // Burn any refresh tokens still bound to the source tenant_user — sessions must be
    // re-established under the new tenant explicitly.
    int revokedTokens =
        refreshTokenRepo.revokeAllByTenantUserId(
            c.getTenantUserId(), RevokedReason.ADMIN_FORCED, OffsetDateTime.now(ZoneOffset.UTC));

    int updated =
        credentialRepo.reassignTenant(
            credentialId, sourceTenantId, targetTenantId, targetTenantUserId);
    if (updated != 1) {
      throw new BusinessException(
          ErrorCode.INTERNAL_SERVER_ERROR,
          "reassign affected " + updated + " rows (expected 1) — RLS may be blocking the write");
    }
    Map<String, Object> payload =
        Map.of(
            "sourceTenantId",
            sourceTenantId.toString(),
            "targetTenantId",
            targetTenantId.toString(),
            "targetTenantUserId",
            targetTenantUserId.toString(),
            "refreshTokensRevoked",
            revokedTokens,
            "policyDiff",
            compat.diff());
    // Append audit under the source chain (forensics for the losing tenant) and again under the
    // target chain (so the gaining tenant can see the import in its own log).
    auditAt(sourceTenantId, c.getId(), payload);
    auditAt(targetTenantId, c.getId(), payload);
    log.info(
        "credential.reassign credentialDbId={} {}→{} user={} refreshTokensRevoked={}",
        credentialId,
        sourceTenantId,
        targetTenantId,
        targetTenantUserId,
        revokedTokens);
    // Reload under the new tenant context so the returned view shows post-move state.
    try {
      TenantContextHolder.set(
          new TenantContext(targetTenantId, "admin-reassign:" + targetTenantId));
      Credential reloaded =
          credentialRepo
              .findById(credentialId)
              .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
      return CredentialView.from(reloaded);
    } finally {
      TenantContextHolder.clear();
    }
  }

  /**
   * Compares source vs target tenant policy/config and decides whether the credential can survive
   * the move. The audit row records both the diff (for forensics) and the blockers (for the
   * operator). We block — not just warn — when the target would reject the credential it just
   * inherited; otherwise the move silently produces an unusable credential.
   */
  private PolicyCompat comparePolicies(
      Credential c,
      TenantWebauthnConfig srcCfg,
      TenantWebauthnConfig dstCfg,
      UUID sourceTenantId,
      UUID targetTenantId) {
    java.util.List<String> blockers = new java.util.ArrayList<>();
    java.util.Map<String, Object> diff = new java.util.LinkedHashMap<>();

    // origins: target must accept at least one of source's origins, otherwise WebAuthn assertions
    // post-move will fail the origin allowlist check.
    java.util.Set<String> srcOrigins = new java.util.HashSet<>(srcCfg.originList());
    java.util.Set<String> dstOrigins = new java.util.HashSet<>(dstCfg.originList());
    if (java.util.Collections.disjoint(srcOrigins, dstOrigins)) {
      blockers.add("origins disjoint: " + srcOrigins + " vs " + dstOrigins);
    }
    if (!srcOrigins.equals(dstOrigins)) {
      diff.put("origins", java.util.Map.of("source", srcOrigins, "target", dstOrigins));
    }

    // Attestation policy: target must accept this credential's AAGUID and syncable flag, otherwise
    // ceremonies post-move would be rejected at register / authenticate.
    TenantAttestationPolicy srcPol =
        attestationPolicyRepo
            .findByTenantId(sourceTenantId)
            .orElseGet(() -> TenantAttestationPolicy.permissive(sourceTenantId));
    TenantAttestationPolicy dstPol =
        attestationPolicyRepo
            .findByTenantId(targetTenantId)
            .orElseGet(() -> TenantAttestationPolicy.permissive(targetTenantId));
    UUID aaguid = c.getAaguid();
    if (aaguid != null && !dstPol.accepts(aaguid)) {
      blockers.add("target attestation policy rejects aaguid " + aaguid);
    }
    if (aaguid == null && !dstPol.isAllowZeroAaguid()) {
      blockers.add("target attestation policy rejects zero-aaguid credentials");
    }
    if (c.isBackupEligible() && !dstPol.acceptsSyncable(true)) {
      blockers.add("target attestation policy rejects syncable credentials");
    }
    diff.put(
        "policy",
        java.util.Map.of(
            "source",
                java.util.Map.of(
                    "mode", srcPol.getMode().name(),
                    "mdsStrict", srcPol.isMdsStrict(),
                    "allowZeroAaguid", srcPol.isAllowZeroAaguid(),
                    "allowSyncable", srcPol.isAllowSyncable()),
            "target",
                java.util.Map.of(
                    "mode", dstPol.getMode().name(),
                    "mdsStrict", dstPol.isMdsStrict(),
                    "allowZeroAaguid", dstPol.isAllowZeroAaguid(),
                    "allowSyncable", dstPol.isAllowSyncable())));
    return new PolicyCompat(blockers.isEmpty(), blockers, diff);
  }

  private record PolicyCompat(
      boolean compatible, java.util.List<String> blockers, java.util.Map<String, Object> diff) {}

  private void auditAt(UUID tenantId, UUID credentialDbId, Map<String, Object> payload) {
    try {
      TenantContextHolder.set(new TenantContext(tenantId, "admin-reassign:" + tenantId));
      auditService.append(
          AuditEventType.CREDENTIAL_REASSIGNED,
          ActorType.ADMIN,
          null,
          "CREDENTIAL",
          credentialDbId.toString(),
          payload);
    } finally {
      TenantContextHolder.clear();
    }
  }

  @Transactional
  public void revoke(UUID credentialId) {
    revoke(credentialId, CredentialRevokedReason.ADMIN_FORCED);
  }

  /**
   * RP-facing revoke: same IDOR-defence as {@link #renameForUser}. Always uses {@code USER_REQUEST}
   * as the revocation reason — the RP-facing API is by definition the end-user dropping their own
   * key. Admin revoke (with explicit reason) keeps using {@link #revoke(UUID,
   * CredentialRevokedReason)}.
   */
  @Transactional
  public void revokeForUser(UUID credentialId, String externalUserId) {
    Credential c = lookupOwnedBy(credentialId, externalUserId);
    // Tag the actor in the log so the RP-path revocation is grep-distinguishable from admin
    // revocations sharing the same doRevoke() body (which logs credential.revoke.* generically).
    log.info(
        "credential.revoke.rp tenantId={} tenantUserId={} credentialDbId={} externalUserId={}",
        c.getTenantId(),
        c.getTenantUserId(),
        c.getId(),
        externalUserId);
    doRevoke(c, CredentialRevokedReason.USER_REQUEST);
  }

  @Transactional
  public void revoke(UUID credentialId, CredentialRevokedReason reason) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    doRevoke(c, reason);
  }

  /**
   * Platform Operator manual unsuspend. Restores ACTIVE; preserves suspendedAt/Reason for
   * forensics; sets unsuspendedAt/By. No refresh token re-issue — user must complete a fresh
   * assertion to receive a new session.
   */
  @Transactional
  public CredentialView unsuspend(UUID credentialId, String actorId) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    String previousReason = c.getSuspendedReason() == null ? "" : c.getSuspendedReason();
    c.unsuspend(actorId); // throws CREDENTIAL_INVALID_STATE on wrong state
    auditService.append(
        AuditEventType.CREDENTIAL_UNSUSPENDED,
        ActorType.ADMIN,
        actorId,
        "CREDENTIAL",
        c.getId().toString(),
        Map.of("previousReason", previousReason));
    log.info(
        "credential.unsuspend tenantId={} credentialDbId={} actor={}",
        c.getTenantId(),
        c.getId(),
        actorId);
    return CredentialView.from(c);
  }

  private Credential lookupOwnedBy(UUID credentialId, String externalUserId) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    TenantUser owner =
        tenantUserRepo
            .findByExternalId(externalUserId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    if (!c.getTenantUserId().equals(owner.getId())) {
      // Deliberately the same error code as "not found" — leaking the existence of another user's
      // credential would let an attacker enumerate by trial.
      log.warn(
          "credential.ownership.mismatch credentialDbId={} requestedExternalUserId={} "
              + "actualTenantUserId={}",
          credentialId,
          externalUserId,
          c.getTenantUserId());
      // Counter drives the "sustained IDOR probing" alert. Single mismatches happen during normal
      // integration testing; a sustained increase points at a buggy RP or a deliberate scan.
      metrics.getOwnershipMismatches().increment();
      throw new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND);
    }
    return c;
  }

  private void doRevoke(Credential c, CredentialRevokedReason reason) {
    c.revoke(reason);
    // Burn outstanding refresh tokens of the same end-user — otherwise stale sessions can keep
    // refreshing access tokens after the credential is gone (P0-1 finding).
    int revokedTokens =
        refreshTokenRepo.revokeAllByTenantUserId(
            c.getTenantUserId(),
            RevokedReason.CREDENTIAL_REVOKED,
            OffsetDateTime.now(ZoneOffset.UTC));
    auditService.append(
        AuditEventType.CREDENTIAL_REVOKED,
        ActorType.END_USER,
        c.getTenantUserId().toString(),
        "CREDENTIAL",
        c.getId().toString(),
        Map.of("reason", reason.name(), "refreshTokensRevoked", revokedTokens));
    log.info(
        "credential.revoke tenantId={} tenantUserId={} credentialDbId={} reason={} refreshTokensRevoked={}",
        c.getTenantId(),
        c.getTenantUserId(),
        c.getId(),
        reason,
        revokedTokens);
  }
}
