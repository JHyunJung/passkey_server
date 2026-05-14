package com.crosscert.passkey.credential.repository;

import com.crosscert.passkey.credential.domain.Credential;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

  Optional<Credential> findByCredentialId(String credentialId);

  List<Credential> findAllByTenantUserId(UUID tenantUserId);
}
