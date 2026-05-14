package com.crosscert.passkey.credential.service;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.repository.TenantWebauthnConfigRepository;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TenantWebauthnConfigService {

  private final TenantWebauthnConfigRepository repo;

  @Transactional(readOnly = true)
  public TenantWebauthnConfig requireCurrent() {
    UUID tenantId = TenantContextHolder.required().tenantId();
    return repo.findByTenantId(tenantId)
        .orElseThrow(() -> new BusinessException(ErrorCode.WEBAUTHN_CONFIG_NOT_FOUND));
  }
}
