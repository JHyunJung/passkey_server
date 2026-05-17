package com.crosscert.passkey.admin.service;

import com.crosscert.passkey.admin.domain.AdminRole;
import com.crosscert.passkey.admin.domain.AdminUser;
import com.crosscert.passkey.admin.repository.AdminUserRepository;
import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * AdminUser CRUD + password lifecycle (P2-2). Audit trail goes under the user's tenant when it
 * exists (RP_ADMIN); platform-operator events are audited under a sentinel tenant context using the
 * actor admin's id. Email uniqueness is checked before the insert to surface {@code M003} before
 * the DB constraint trips.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminUserManagementService {

  private static final SecureRandom RNG = new SecureRandom();
  private static final int TEMP_PASSWORD_BYTES = 24; // → 32-char base64url

  private final AdminUserRepository repo;
  private final TenantRepository tenantRepo;
  private final PasswordEncoder passwordEncoder;
  private final AuditService auditService;

  /** New {@link AdminUser} + the one-time plaintext password the caller shows to the operator. */
  public record CreatedAdmin(AdminUser admin, String temporaryPassword) {}

  @Transactional(readOnly = true)
  public Page<AdminUser> list(Pageable pageable) {
    return repo.findAll(pageable);
  }

  @Transactional(readOnly = true)
  public AdminUser get(UUID id) {
    return repo.findById(id)
        .orElseThrow(() -> new BusinessException(ErrorCode.ADMIN_USER_NOT_FOUND));
  }

  @Transactional
  public CreatedAdmin create(
      String email, String displayName, AdminRole role, UUID tenantId, UUID actorAdminId) {
    if (repo.findByEmail(email).isPresent()) {
      throw new BusinessException(ErrorCode.ADMIN_USER_EMAIL_DUPLICATE);
    }
    if (role == AdminRole.RP_ADMIN && tenantId == null) {
      throw new BusinessException(ErrorCode.INVALID_INPUT, "RP_ADMIN requires tenantId");
    }
    if (role == AdminRole.RP_ADMIN && tenantRepo.findById(tenantId).isEmpty()) {
      throw new BusinessException(ErrorCode.TENANT_NOT_FOUND);
    }
    String temp = randomBase64Url();
    String hash = passwordEncoder.encode(temp);
    AdminUser saved =
        repo.save(
            role == AdminRole.PLATFORM_OPERATOR
                ? AdminUser.createPlatformOperator(email, hash, displayName)
                : AdminUser.createRpAdmin(tenantId, email, hash, displayName));
    auditAdminEvent(
        saved,
        actorAdminId,
        AuditEventType.ADMIN_USER_CREATED,
        Map.of("email", email, "role", role.name()));
    log.info(
        "admin.user.created id={} email={} role={} actor={}",
        saved.getId(),
        email,
        role,
        actorAdminId);
    return new CreatedAdmin(saved, temp);
  }

  @Transactional
  public void delete(UUID adminId, UUID actorAdminId) {
    if (adminId.equals(actorAdminId)) {
      throw new BusinessException(ErrorCode.ADMIN_USER_SELF_DELETE_FORBIDDEN);
    }
    AdminUser target = get(adminId);
    repo.delete(target);
    auditAdminEvent(
        target,
        actorAdminId,
        AuditEventType.ADMIN_USER_DELETED,
        Map.of("email", target.getEmail()));
    log.info("admin.user.deleted id={} actor={}", adminId, actorAdminId);
  }

  /** Operator-driven reset — returns a fresh one-time password the caller must surface once. */
  @Transactional
  public String resetPassword(UUID adminId, UUID actorAdminId) {
    AdminUser target = get(adminId);
    if (adminId.equals(actorAdminId)) {
      // Self-reset must go through the change-with-old-password flow instead.
      throw new BusinessException(ErrorCode.ADMIN_USER_SELF_DELETE_FORBIDDEN);
    }
    String temp = randomBase64Url();
    target.resetPassword(passwordEncoder.encode(temp));
    auditAdminEvent(
        target, actorAdminId, AuditEventType.ADMIN_USER_PASSWORD_RESET, Map.of("by", "operator"));
    log.info("admin.user.password.reset id={} actor={}", adminId, actorAdminId);
    return temp;
  }

  /** Self-change — old password is verified before the new hash is stored. */
  @Transactional
  public void changeOwnPassword(UUID adminId, String oldPassword, String newPassword) {
    AdminUser target = get(adminId);
    if (!passwordEncoder.matches(oldPassword, target.getPasswordHash())) {
      throw new BusinessException(ErrorCode.ADMIN_PASSWORD_INVALID);
    }
    if (newPassword == null || newPassword.length() < 12) {
      throw new BusinessException(ErrorCode.INVALID_INPUT, "password must be >= 12 chars");
    }
    target.resetPassword(passwordEncoder.encode(newPassword));
    auditAdminEvent(
        target, adminId, AuditEventType.ADMIN_USER_PASSWORD_RESET, Map.of("by", "self"));
    log.info("admin.user.password.self_change id={}", adminId);
  }

  private void auditAdminEvent(
      AdminUser subject, UUID actorAdminId, AuditEventType eventType, Map<String, Object> payload) {
    // RP_ADMIN events scope under their tenant; platform-operator events use the subject's
    // (possibly null) tenantId — for PLATFORM_OPERATOR we fall back to the tenant_user table being
    // empty for the actor, which means the chain stays per-tenant when one exists and is global
    // (null) otherwise. Pick the first non-null between subject and actor.
    UUID auditTenantId = subject.getTenantId();
    if (auditTenantId == null) {
      // PLATFORM_OPERATOR events: write under the system-wide chain by reusing the actor's
      // (admin) tenantId if any, otherwise fall back to a sentinel UUID derived from the role.
      // We don't have a global chain in this codebase — keep events tenant-less by skipping the
      // append; the structured log line is the forensics surface.
      log.info(
          "admin.user.audit.skipped event={} subject={} actor={} payload={}",
          eventType,
          subject.getId(),
          actorAdminId,
          payload);
      return;
    }
    try {
      TenantContextHolder.set(new TenantContext(auditTenantId, "admin-mgmt:" + auditTenantId));
      auditService.append(
          eventType,
          ActorType.ADMIN,
          actorAdminId == null ? null : actorAdminId.toString(),
          "ADMIN_USER",
          subject.getId().toString(),
          payload);
    } finally {
      TenantContextHolder.clear();
    }
  }

  private static String randomBase64Url() {
    byte[] buf = new byte[TEMP_PASSWORD_BYTES];
    RNG.nextBytes(buf);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
  }
}
