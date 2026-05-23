package com.crosscert.passkey.auth.jwt.repository;

import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Cross-tenant bulk revoke of refresh tokens on the {@code APP_ADMIN} (VPD-exempt) data source.
 * Used by {@code MdsRevocationScanService} to burn every live refresh token of users whose
 * credentials were just SUSPENDED — a single UPDATE that crosses tenant predicates.
 *
 * <p>The per-tenant, per-user revoke path is unchanged: {@link RefreshTokenRepository}{@code
 * #revokeAllByTenantUserId(UUID, ...)} still serves the ordinary lifecycle (logout, single
 * credential revoke). Only the cross-tenant bulk path lives here.
 *
 * <p>Gated on {@code passkey.admin.enabled=true} — same switch that activates {@code
 * AdminJdbcConfig} (and therefore the {@code adminJdbcTemplate} / {@code adminTransactionManager}
 * beans this writer depends on). Mirrors {@code CredentialAdminWriter} / {@code ApiKeyAdminWriter}.
 */
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class RefreshTokenAdminWriter {

  private final NamedParameterJdbcTemplate admin;

  /**
   * Constructor parameter is named {@code adminJdbcTemplate} so Spring resolves the dependency by
   * bean name — the established pattern in {@code ApiKeyAdminWriter} / {@code
   * CredentialAdminWriter}.
   */
  public RefreshTokenAdminWriter(NamedParameterJdbcTemplate adminJdbcTemplate) {
    this.admin = adminJdbcTemplate;
  }

  /**
   * Revoke every live ({@code revoked_at IS NULL}) refresh token whose {@code tenant_user_id} is in
   * {@code tenantUserIds}. Idempotent — already-revoked rows are skipped via the {@code WHERE
   * revoked_at IS NULL} guard, so calling this twice in a row will affect 0 the second time.
   *
   * @return number of rows actually transitioned to revoked.
   */
  @Transactional("adminTransactionManager")
  public int revokeAllByTenantUserIds(Set<UUID> tenantUserIds, RevokedReason reason) {
    if (tenantUserIds == null || tenantUserIds.isEmpty()) {
      return 0;
    }
    // Expand the IN list manually — Spring's named-param list expansion on RAW(16) IN-clauses is
    // finicky on Oracle, so we bind each id individually. Same idiom as CredentialAdminWriter.
    StringBuilder inClause = new StringBuilder();
    MapSqlParameterSource params = new MapSqlParameterSource().addValue("reason", reason.name());
    int i = 0;
    for (UUID uid : tenantUserIds) {
      if (i > 0) inClause.append(',');
      inClause.append("HEXTORAW(:u").append(i).append(")");
      params.addValue("u" + i, uuidToHex(uid));
      i++;
    }
    return admin.update(
        "UPDATE refresh_token "
            + "   SET revoked_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), "
            + "       revoked_reason = :reason, "
            + "       updated_at = SYSTIMESTAMP "
            + " WHERE revoked_at IS NULL "
            + "   AND tenant_user_id IN ("
            + inClause
            + ")",
        params);
  }

  private static String uuidToHex(UUID u) {
    ByteBuffer b = ByteBuffer.allocate(16);
    b.putLong(u.getMostSignificantBits());
    b.putLong(u.getLeastSignificantBits());
    return HexFormat.of().formatHex(b.array());
  }
}
