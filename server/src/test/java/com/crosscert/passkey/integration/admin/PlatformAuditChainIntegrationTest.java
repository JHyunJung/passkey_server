package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.admin.service.PlatformAuditChainService;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.ChainStatus;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.VerifyAllResult;
import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * cross-tenant audit chain 상태 집계 + verifyAll() 직렬 검증을 실제 Oracle 위에서 실행. 한 tenant의 audit row hash를
 * 인위적으로 깨뜨려 tampered tenant가 응답에 등장하는지, 다른 tenant는 영향이 없는지 확인한다.
 */
class PlatformAuditChainIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired private PlatformAuditChainService chainService;
  @Autowired private AuditService auditService;
  @Autowired private TenantSeed tenantSeed;

  @Autowired
  @Qualifier("adminDataSource")
  private DataSource adminDataSource;

  private NamedParameterJdbcTemplate adminJdbc;

  @BeforeEach
  void setupJdbc() {
    adminJdbc = new NamedParameterJdbcTemplate(adminDataSource);
  }

  @Test
  void status_marks_tampered_tenant_and_keeps_others_intact() {
    UUID intactTenant = tenantSeed.createTenant("chain-intact-" + suffix());
    UUID tamperedTenant = tenantSeed.createTenant("chain-tampered-" + suffix());

    // 정상 audit row — auditService.append가 hash chain을 자기 일관성 있게 채운다.
    appendUnderTenant(intactTenant, "actor-1", "subj-1");
    appendUnderTenant(tamperedTenant, "actor-2", "subj-2");

    // tamperedTenant의 row_hash 손상
    corruptRowHash(tamperedTenant);

    ChainStatus status = chainService.status();

    assertThat(status.tamperedTenants())
        .as("tamperedTenants에 손상된 tenant 등장")
        .anyMatch(s -> s.tenantId().equals(tamperedTenant));
    assertThat(status.tamperedTenants())
        .as("tamperedTenants에 intact tenant는 없음")
        .noneMatch(s -> s.tenantId().equals(intactTenant));

    assertThat(status.perTenant())
        .filteredOn(r -> r.tenantId().equals(intactTenant))
        .singleElement()
        .satisfies(r -> assertThat(r.status()).isEqualTo("INTACT"));
    assertThat(status.perTenant())
        .filteredOn(r -> r.tenantId().equals(tamperedTenant))
        .singleElement()
        .satisfies(r -> assertThat(r.status()).isEqualTo("TAMPERED"));
  }

  @Test
  void verifyAll_returns_per_tenant_results_including_tampered() {
    UUID intactTenant = tenantSeed.createTenant("verify-intact-" + suffix());
    UUID tamperedTenant = tenantSeed.createTenant("verify-tampered-" + suffix());

    appendUnderTenant(intactTenant, "actor-a", "subj-a");
    appendUnderTenant(tamperedTenant, "actor-b", "subj-b");

    corruptRowHash(tamperedTenant);

    VerifyAllResult result = chainService.verifyAll();

    assertThat(result.tenantsChecked()).isGreaterThanOrEqualTo(2);

    assertThat(result.perTenant())
        .filteredOn(r -> r.tenantId().equals(intactTenant))
        .singleElement()
        .satisfies(r -> assertThat(r.intact()).isTrue());

    assertThat(result.perTenant())
        .filteredOn(r -> r.tenantId().equals(tamperedTenant))
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.intact()).isFalse();
              assertThat(r.tamperedRowCount()).isGreaterThanOrEqualTo(1);
            });
  }

  // ---- helpers ----

  /**
   * AuditService.append 호출은 VPD-bound이므로 TenantContextHolder를 set한 뒤 호출. TenantSeed.withTenant 헬퍼가
   * 자동으로 set/clear한다.
   */
  private void appendUnderTenant(UUID tenantId, String actorId, String subjectId) {
    tenantSeed.withTenant(
        tenantId,
        () ->
            auditService.append(
                AuditEventType.CREDENTIAL_REGISTERED,
                ActorType.END_USER,
                actorId,
                "CREDENTIAL",
                subjectId,
                Map.of()));
  }

  private void corruptRowHash(UUID tenantId) {
    adminJdbc.update(
        "UPDATE audit_log SET row_hash = 'corrupted-by-test' WHERE tenant_id = HEXTORAW(:tid)",
        new MapSqlParameterSource().addValue("tid", uuidToHex(tenantId)));
  }

  private static String suffix() {
    return UUID.randomUUID().toString().substring(0, 8);
  }

  private static String uuidToHex(UUID u) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(u.getMostSignificantBits());
    bb.putLong(u.getLeastSignificantBits());
    return java.util.HexFormat.of().formatHex(bb.array());
  }
}
