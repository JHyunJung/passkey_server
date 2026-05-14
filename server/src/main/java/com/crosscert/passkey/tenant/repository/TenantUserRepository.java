package com.crosscert.passkey.tenant.repository;

import com.crosscert.passkey.tenant.domain.TenantUser;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantUserRepository extends JpaRepository<TenantUser, UUID> {

  Optional<TenantUser> findByExternalId(String externalId);
}
