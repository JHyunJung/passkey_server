package com.crosscert.passkey.credential.repository;

import com.crosscert.passkey.credential.domain.TenantAttestationPolicy;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantAttestationPolicyRepository
    extends JpaRepository<TenantAttestationPolicy, UUID> {

  Optional<TenantAttestationPolicy> findByTenantId(UUID tenantId);
}
