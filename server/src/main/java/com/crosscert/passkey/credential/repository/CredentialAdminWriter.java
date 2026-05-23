package com.crosscert.passkey.credential.repository;

import com.crosscert.passkey.fido2.mds.StatusReport;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bulk credential writes that VPD predicates would otherwise block. Runs on the {@code APP_ADMIN}
 * (EXEMPT) data source so SUSPEND can span tenants in a single UPDATE.
 *
 * <p>Used by {@code MdsRevocationScanService} for the post-registration MDS revocation pipeline.
 * The corresponding single-credential / per-tenant lifecycle path stays on {@code
 * CredentialLifecycleService} + JPA.
 *
 * <p>Gated on {@code passkey.admin.enabled=true} — same switch that activates {@code
 * AdminJdbcConfig} (and therefore the {@code adminJdbcTemplate} / {@code adminTransactionManager}
 * beans this writer depends on). Mirrors {@code ApiKeyAdminWriter}'s gating exactly. {@code
 * @ConditionalOnBean} was considered but is fragile when the depended-on bean is declared in the
 * same context refresh — the property-based gate is the established project convention.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
public class CredentialAdminWriter {

  private final NamedParameterJdbcTemplate admin;

  /**
   * Constructor parameter is named {@code adminJdbcTemplate} so Spring resolves the dependency by
   * bean name — the established pattern in {@code ApiKeyAdminWriter}. No {@code @Qualifier} needed.
   */
  public CredentialAdminWriter(NamedParameterJdbcTemplate adminJdbcTemplate) {
    this.admin = adminJdbcTemplate;
  }

  /** Identification tuple returned from {@link #suspendByAaguids}. */
  public record SuspendedRow(UUID id, UUID tenantId, UUID tenantUserId, UUID aaguid) {}

  /**
   * Suspend all {@code ACTIVE} credentials whose AAGUID is in {@code aaguids.keySet()}.
   *
   * <p>Two-step pattern (Oracle multi-row RETURNING isn't supported on plain JDBC):
   *
   * <ol>
   *   <li>{@code SELECT ... FOR UPDATE} to lock target rows and collect identifiers.
   *   <li>Batch {@code UPDATE ... WHERE id=? AND status='ACTIVE'} with a status guard so a
   *       concurrent ceremony that already moved the row to REVOKED isn't silently overwritten.
   * </ol>
   *
   * @return rows that transitioned ACTIVE → SUSPENDED (empty if none).
   */
  @Transactional("adminTransactionManager")
  public List<SuspendedRow> suspendByAaguids(
      Map<UUID, StatusReport> aaguids, long mdsBlobSerial) {
    if (aaguids == null || aaguids.isEmpty()) {
      return List.of();
    }

    // Build IN list of HEXTORAW(?) bindings manually — Spring's named-param list expansion on
    // RAW(16) IN-clauses is finicky on Oracle, so we expand at SQL composition time.
    StringBuilder inClause = new StringBuilder();
    MapSqlParameterSource selectParams = new MapSqlParameterSource();
    int i = 0;
    for (UUID aaguid : aaguids.keySet()) {
      if (i > 0) inClause.append(',');
      inClause.append("HEXTORAW(:a").append(i).append(")");
      selectParams.addValue("a" + i, uuidToHex(aaguid));
      i++;
    }

    List<SuspendedRow> targets =
        admin.query(
            "SELECT id, tenant_id, tenant_user_id, aaguid "
                + "  FROM credential "
                + " WHERE status = 'ACTIVE' "
                + "   AND aaguid IN ("
                + inClause
                + ") "
                + "   FOR UPDATE",
            selectParams,
            (rs, n) ->
                new SuspendedRow(
                    uuidFromBytes(rs.getBytes("id")),
                    uuidFromBytes(rs.getBytes("tenant_id")),
                    uuidFromBytes(rs.getBytes("tenant_user_id")),
                    uuidFromBytes(rs.getBytes("aaguid"))));

    if (targets.isEmpty()) {
      log.info(
          "mds.scan.suspend.nothingToDo aaguids={} blobSerial={}",
          aaguids.size(),
          mdsBlobSerial);
      return targets;
    }

    SqlParameterSource[] batch =
        targets.stream()
            .map(
                r ->
                    new MapSqlParameterSource()
                        .addValue("id", uuidToHex(r.id()))
                        .addValue(
                            "reason",
                            "MDS_REVOKED:" + aaguids.get(r.aaguid()).name()))
            .toArray(SqlParameterSource[]::new);

    int[] affected =
        admin.batchUpdate(
            "UPDATE credential "
                + "   SET status = 'SUSPENDED', "
                + "       suspended_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), "
                + "       suspended_reason = :reason, "
                + "       updated_at = SYSTIMESTAMP "
                + " WHERE id = HEXTORAW(:id) AND status = 'ACTIVE'",
            batch);

    int total = 0;
    for (int a : affected) total += a;
    log.info(
        "mds.scan.suspend.applied targets={} affected={} blobSerial={}",
        targets.size(),
        total,
        mdsBlobSerial);
    return targets;
  }

  /**
   * Distinct {@code tenant_user_id}s that have ≥1 SUSPENDED credential AND ≥1 unrevoked refresh
   * token. Used by scan §5.2 boost to clean up tokens that survived an earlier F5 (token revoke
   * failure after credential SUSPENDED succeeded).
   */
  @Transactional(value = "adminTransactionManager", readOnly = true)
  public Set<UUID> tenantUserIdsWithSuspendedCredentialAndLiveToken() {
    List<byte[]> raws =
        admin.query(
            "SELECT DISTINCT c.tenant_user_id "
                + "  FROM credential c "
                + "  JOIN refresh_token t ON t.tenant_user_id = c.tenant_user_id "
                + " WHERE c.status = 'SUSPENDED' AND t.revoked_at IS NULL",
            (rs, n) -> rs.getBytes(1));
    LinkedHashSet<UUID> out = new LinkedHashSet<>();
    for (byte[] b : raws) out.add(uuidFromBytes(b));
    return out;
  }

  // ---- helpers --------------------------------------------------------------------------------
  private static String uuidToHex(UUID u) {
    return HexFormat.of().formatHex(uuidBytes(u));
  }

  private static byte[] uuidBytes(UUID u) {
    ByteBuffer b = ByteBuffer.allocate(16);
    b.putLong(u.getMostSignificantBits());
    b.putLong(u.getLeastSignificantBits());
    return b.array();
  }

  private static UUID uuidFromBytes(byte[] raw) {
    ByteBuffer bb = ByteBuffer.wrap(raw);
    long high = bb.getLong();
    long low = bb.getLong();
    return new UUID(high, low);
  }
}
