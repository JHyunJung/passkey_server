package com.crosscert.passkey.integration.support;

import com.crosscert.passkey.tenant.context.TenantContext;
import com.crosscert.passkey.tenant.context.TenantContextHolder;
import com.crosscert.passkey.tenant.domain.Tenant;
import com.crosscert.passkey.tenant.domain.TenantUser;
import com.crosscert.passkey.tenant.repository.TenantRepository;
import com.crosscert.passkey.tenant.repository.TenantUserRepository;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tenant test fixtures. The repository methods are all {@code @Transactional} — the tenant context
 * is set/cleared explicitly per call so isolation tests can verify cross-tenant access boundaries.
 * Registered as a bean in {@code TestSupportConfig}.
 */
@RequiredArgsConstructor
public class TenantSeed {

  private final TenantRepository tenantRepository;
  private final TenantUserRepository tenantUserRepository;
  private final TransactionTemplate txTemplate;

  /** Inserts a tenant. Bypasses RLS context — the `tenant` table is RLS-exempt. */
  @Transactional
  public UUID createTenant(String slug) {
    Tenant t = Tenant.create("Tenant-" + slug, slug);
    return tenantRepository.save(t).getId();
  }

  /** Inserts a tenant_user under the given tenant. Sets/clears context around the call. */
  public UUID createUser(UUID tenantId, String externalId) {
    return withTenant(
        tenantId,
        () ->
            txTemplate.execute(
                status -> {
                  TenantUser user = TenantUser.create(tenantId, externalId, externalId);
                  return tenantUserRepository.save(user).getId();
                }));
  }

  public <T> T withTenant(UUID tenantId, Supplier<T> action) {
    try {
      TenantContextHolder.set(new TenantContext(tenantId, "tenant-" + tenantId));
      return action.get();
    } finally {
      TenantContextHolder.clear();
    }
  }

  public void withTenant(UUID tenantId, Runnable action) {
    withTenant(
        tenantId,
        () -> {
          action.run();
          return null;
        });
  }

  public <T> T withoutTenant(Supplier<T> action) {
    TenantContextHolder.clear();
    return action.get();
  }

  public void withoutTenant(Runnable action) {
    withoutTenant(
        () -> {
          action.run();
          return null;
        });
  }
}
