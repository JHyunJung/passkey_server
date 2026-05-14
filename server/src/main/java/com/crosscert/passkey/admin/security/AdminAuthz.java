package com.crosscert.passkey.admin.security;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import java.util.UUID;
import org.springframework.security.core.context.SecurityContextHolder;

public final class AdminAuthz {

  private AdminAuthz() {}

  public static AdminPrincipal currentPrincipal() {
    Object p = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    if (!(p instanceof AdminPrincipal ap)) {
      throw new BusinessException(ErrorCode.ADMIN_LOGIN_REQUIRED);
    }
    return ap;
  }

  /**
   * Enforces that the current admin may act on the given tenant. Platform Operator may act on any
   * tenant; RP_ADMIN may act only on their own. Also sets {@link TenantContextHolder} so subsequent
   * DB calls hit RLS with the right tenant.
   */
  public static void requireTenantAccess(UUID pathTenantId) {
    AdminPrincipal admin = currentPrincipal();
    if (!admin.isPlatformOperator()) {
      if (admin.tenantId() == null || !admin.tenantId().equals(pathTenantId)) {
        throw new BusinessException(ErrorCode.ADMIN_ROLE_FORBIDDEN);
      }
    }
    TenantContextHolder.set(new TenantContext(pathTenantId, "admin:" + pathTenantId));
  }

  public static void requirePlatformOperator() {
    AdminPrincipal admin = currentPrincipal();
    if (!admin.isPlatformOperator()) {
      throw new BusinessException(ErrorCode.ADMIN_ROLE_FORBIDDEN);
    }
  }
}
