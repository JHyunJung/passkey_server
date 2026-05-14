package com.crosscert.passkey.auth.apikey.repository;

import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

  Optional<ApiKey> findByPrefix(String prefix);
}
