package com.crosscert.passkey.admin.repository;

import com.crosscert.passkey.admin.domain.AdminUser;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminUserRepository extends JpaRepository<AdminUser, UUID> {

  Optional<AdminUser> findByEmail(String email);
}
