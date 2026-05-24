package com.crosscert.passkey.integration.support;

import com.crosscert.passkey.auth.jwt.domain.RevokedReason;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Refresh-token seeder for admin-side slice/integration tests. Uses the admin (VPD-exempt) data
 * source so tests can seed rows for any tenant without first having to set the tenant context.
 * Mirrors the inline {@code insertToken(...)} helper already used in {@code
 * RefreshTokenAdminWriterSliceTest} — extracted here so the admin user-view tests can reuse it.
 *
 * <p>Registered as a bean in {@link TestSupportConfig}.
 */
public class RefreshTokenSeed {

  private final NamedParameterJdbcTemplate admin;

  public RefreshTokenSeed(@Qualifier("adminJdbcTemplate") NamedParameterJdbcTemplate admin) {
    this.admin = admin;
  }

  /** Insert a live (unrevoked, not-yet-expired) token. */
  public UUID insertLive(UUID tenantId, UUID userId, OffsetDateTime expiresAt) {
    UUID id = UUID.randomUUID();
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :exp, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("exp", expiresAt));
    return id;
  }

  /**
   * Insert a token whose expiry is already in the past (no revoked_at). Same row shape as {@link
   * #insertLive} — only the {@code expiresAt} value differs.
   */
  public UUID insertExpired(UUID tenantId, UUID userId, OffsetDateTime pastExpires) {
    return insertLive(tenantId, userId, pastExpires);
  }

  /**
   * Insert a token already revoked. Uses {@link RevokedReason#ROTATED} by default — matches the
   * existing inline {@code insertToken(... "ROTATED" ...)} pattern in {@code
   * RefreshTokenAdminWriterSliceTest}.
   */
  public UUID insertRevoked(UUID tenantId, UUID userId, OffsetDateTime expiresAt) {
    return insertRevoked(tenantId, userId, expiresAt, RevokedReason.ROTATED);
  }

  /**
   * Variant of {@link #insertRevoked(UUID, UUID, OffsetDateTime)} that lets the caller pick the
   * reason.
   */
  public UUID insertRevoked(
      UUID tenantId, UUID userId, OffsetDateTime expiresAt, RevokedReason reason) {
    UUID id = UUID.randomUUID();
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    admin.update(
        "INSERT INTO refresh_token "
            + "(id, tenant_id, tenant_user_id, issued_at, expires_at, "
            + " revoked_at, revoked_reason, created_at, updated_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), HEXTORAW(:uid), :now, :exp, "
            + "        :now, :reason, :now, :now)",
        new MapSqlParameterSource()
            .addValue("id", hex(id))
            .addValue("tid", hex(tenantId))
            .addValue("uid", hex(userId))
            .addValue("now", now)
            .addValue("exp", expiresAt)
            .addValue("reason", reason.name()));
    return id;
  }

  /** UUID → 32-char hex for Oracle {@code HEXTORAW}. */
  private static String hex(UUID u) {
    return u.toString().replace("-", "");
  }
}
