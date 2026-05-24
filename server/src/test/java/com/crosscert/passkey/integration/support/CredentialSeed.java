package com.crosscert.passkey.integration.support;

import com.crosscert.passkey.credential.domain.Credential;
import com.crosscert.passkey.credential.domain.CredentialStatus;
import com.crosscert.passkey.credential.repository.CredentialRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Credential test fixtures via the normal VPD-applied JPA path. Counterpart to {@link TenantSeed}:
 * sets/clears the tenant context around each save so the runtime data source's VPD policy admits
 * the insert. Registered as a bean in {@code TestSupportConfig}.
 *
 * <p>Use this when a slice/integration test needs realistic {@code credential} rows visible through
 * the runtime user. For cross-tenant or VPD-bypass seeding, the dedicated MDS slice tests still go
 * through {@code adminJdbcTemplate} directly — that path stays inline because it is rare.
 */
@RequiredArgsConstructor
public class CredentialSeed {

  private final CredentialRepository credentialRepository;
  private final TenantSeed tenantSeed;
  private final TransactionTemplate txTemplate;

  /** Inserts a credential under {@code tenantUserId} with the given status. Returns its id. */
  public UUID create(UUID tenantId, UUID tenantUserId, CredentialStatus status) {
    return tenantSeed.withTenant(
        tenantId,
        () ->
            txTemplate.execute(
                s -> {
                  Credential credential =
                      Credential.create(
                          tenantId,
                          tenantUserId,
                          "cred-" + UUID.randomUUID(),
                          new byte[] {1, 2, 3},
                          UUID.randomUUID(),
                          "internal",
                          "userHandle",
                          0L,
                          false,
                          false);
                  // Credential.create always returns ACTIVE — flip to SUSPENDED / REVOKED via
                  // the domain methods so the matching audit columns (suspendedAt, revokedAt …)
                  // stay consistent with production rows.
                  switch (status) {
                    case ACTIVE -> {
                      // already ACTIVE
                    }
                    case SUSPENDED -> credential.suspend("seed");
                    case REVOKED -> credential.revoke();
                  }
                  return credentialRepository.save(credential).getId();
                }));
  }
}
