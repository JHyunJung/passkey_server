package com.crosscert.passkey.credential.repository;

import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantWebauthnConfigRepository extends JpaRepository<TenantWebauthnConfig, UUID> {

  Optional<TenantWebauthnConfig> findByTenantId(UUID tenantId);
}
