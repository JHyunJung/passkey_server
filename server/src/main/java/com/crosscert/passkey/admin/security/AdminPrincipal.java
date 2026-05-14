package com.crosscert.passkey.admin.security;

import com.crosscert.passkey.admin.domain.AdminRole;
import java.util.UUID;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Spring Security principal for an authenticated admin. Carries the resolved {@code tenantId} (null
 * for Platform Operators) so authorization checks can compare against the path tenant id.
 */
public class AdminPrincipal extends User {

  private final UUID adminId;
  private final UUID tenantId;
  private final AdminRole role;
  private final String displayName;

  public AdminPrincipal(
      UUID adminId, UUID tenantId, AdminRole role, String email, String displayName) {
    super(
        email,
        "",
        java.util.List.<GrantedAuthority>of(new SimpleGrantedAuthority("ROLE_" + role.name())));
    this.adminId = adminId;
    this.tenantId = tenantId;
    this.role = role;
    this.displayName = displayName;
  }

  public UUID adminId() {
    return adminId;
  }

  public UUID tenantId() {
    return tenantId;
  }

  public AdminRole role() {
    return role;
  }

  public String displayName() {
    return displayName;
  }

  public boolean isPlatformOperator() {
    return role == AdminRole.PLATFORM_OPERATOR;
  }
}
