package com.crosscert.passkey.admin.security;

import com.crosscert.passkey.admin.domain.AdminUser;
import com.crosscert.passkey.admin.repository.AdminUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AdminUserDetailsService implements UserDetailsService {

  private final AdminUserRepository repo;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    AdminUser a =
        repo.findByEmail(email)
            .filter(AdminUser::isActive)
            .orElseThrow(() -> new UsernameNotFoundException("admin not found: " + email));
    // Wrap as a "shadow" User for password verification by DaoAuthenticationProvider.
    // After successful authentication AdminAuthenticationSuccessHandler re-projects to
    // AdminPrincipal so authorization carries tenantId/role.
    return User.withUsername(a.getEmail())
        .password(a.getPasswordHash())
        .authorities("ROLE_" + a.getRole().name())
        .accountLocked(!a.isActive())
        .build();
  }
}
