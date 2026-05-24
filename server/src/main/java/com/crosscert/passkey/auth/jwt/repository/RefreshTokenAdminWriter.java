package com.crosscert.passkey.auth.jwt.repository;

import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
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

  /**
   * Max bound expressions per IN-clause. Oracle's hard limit is 1000 ({@code ORA-01795}); 500
   * leaves headroom for any additional binds in the same statement and matches a common safe
   * default. An MDS scan that suspends &gt;500 distinct {@code tenant_user_id}s would otherwise
   * raise ORA-01795 here — the credential SUSPEND has already committed in a prior admin tx, so the
   * failure would leave those sessions live until manually fixed.
   */
  public static final int CHUNK_SIZE = 500;

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
   * <p>The id set is partitioned into chunks of at most {@link #CHUNK_SIZE} so the generated {@code
   * IN (...)} list never exceeds Oracle's 1000-expression cap ({@code ORA-01795}). All chunks run
   * in the same {@code adminTransactionManager} transaction — partial failures roll the entire
   * revoke back, so callers still get all-or-nothing semantics.
   *
   * @return number of rows actually transitioned to revoked across all chunks.
   */
  @Transactional("adminTransactionManager")
  public int revokeAllByTenantUserIds(Set<UUID> tenantUserIds, RevokedReason reason) {
    if (tenantUserIds == null || tenantUserIds.isEmpty()) {
      return 0;
    }
    // Chunk to stay under Oracle's 1000-expression IN-list cap (ORA-01795). All chunks share the
    // outer @Transactional so a mid-chunk failure rolls the whole revoke back, preserving
    // all-or-nothing semantics that callers (MdsRevocationScanService) rely on.
    List<UUID> ordered = new ArrayList<>(tenantUserIds);
    int total = 0;
    for (int from = 0; from < ordered.size(); from += CHUNK_SIZE) {
      int to = Math.min(from + CHUNK_SIZE, ordered.size());
      total += revokeChunk(ordered.subList(from, to), reason);
    }
    return total;
  }

  /**
   * Revoke a single IN-list chunk. Sized by the caller to stay under {@link #CHUNK_SIZE}. Must run
   * inside the outer {@link #revokeAllByTenantUserIds} transaction — extracting the JDBC call lets
   * the chunking logic above stay declarative without losing the all-or-nothing rollback.
   */
  private int revokeChunk(List<UUID> chunk, RevokedReason reason) {
    // Expand the IN list manually — Spring's named-param list expansion on RAW(16) IN-clauses is
    // finicky on Oracle, so we bind each id individually. Same idiom as CredentialAdminWriter.
    StringBuilder inClause = new StringBuilder();
    MapSqlParameterSource params = new MapSqlParameterSource().addValue("reason", reason.name());
    for (int i = 0; i < chunk.size(); i++) {
      if (i > 0) inClause.append(',');
      inClause.append("HEXTORAW(:u").append(i).append(")");
      params.addValue("u" + i, uuidToHex(chunk.get(i)));
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
