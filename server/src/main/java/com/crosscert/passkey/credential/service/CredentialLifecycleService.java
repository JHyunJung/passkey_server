package com.crosscert.passkey.credential.service;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.CredentialView;
import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
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
  private final AuditService auditService;

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

  @Transactional
  public void revoke(UUID credentialId) {
    Credential c =
        credentialRepo
            .findById(credentialId)
            .orElseThrow(() -> new BusinessException(ErrorCode.CREDENTIAL_NOT_FOUND));
    c.revoke();
    auditService.append(
        AuditEventType.CREDENTIAL_REVOKED,
        ActorType.END_USER,
        c.getTenantUserId().toString(),
        "CREDENTIAL",
        c.getId().toString(),
        Map.of());
    log.info(
        "credential.revoke tenantId={} tenantUserId={} credentialDbId={}",
        c.getTenantId(),
        c.getTenantUserId(),
        c.getId());
  }
}
