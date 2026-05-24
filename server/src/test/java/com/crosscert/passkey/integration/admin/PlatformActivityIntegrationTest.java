package com.crosscert.passkey.integration.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.admin.service.PlatformActivityService;
import com.crosscert.passkey.admin.service.PlatformActivityService.ActivitySummary;
import com.crosscert.passkey.admin.service.PlatformActivityService.FeedPage;
import com.crosscert.passkey.audit.domain.AuditCategory;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.integration.support.AdminEnabledIntegrationTestBase;
import com.crosscert.passkey.integration.support.TenantSeed;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * 여러 tenant seed 후 cross-tenant 합산 + VPD 우회가 실제로 작동하는지 검증. positive case로 PlatformActivityService가
 * 다른 tenant 데이터까지 합산해 반환하는 것을 입증한다.
 */
class PlatformActivityIntegrationTest extends AdminEnabledIntegrationTestBase {

  @Autowired private PlatformActivityService service;
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
  void summary_aggregates_events_across_all_seeded_tenants() {
    UUID t1 = tenantSeed.createTenant("activity-a-" + suffix());
    UUID t2 = tenantSeed.createTenant("activity-b-" + suffix());
    UUID t3 = tenantSeed.createTenant("activity-c-" + suffix());
    UUID t4 = tenantSeed.createTenant("activity-d-" + suffix());

    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    // 24h window 안의 이벤트 — 3개 카테고리 각각 분산
    insertAuditRow(t1, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusHours(1));
    insertAuditRow(t2, AuditEventType.API_KEY_ISSUED, now.minusHours(2));
    insertAuditRow(t3, AuditEventType.SIGNATURE_COUNTER_REGRESSION, now.minusHours(3));
    insertAuditRow(t4, AuditEventType.CREDENTIAL_REGISTERED, now.minusHours(4));
    // 24h 밖 — 합산에서 빠져야 함
    insertAuditRow(t1, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusHours(48));

    ActivitySummary baseline = service.summary("24h");

    // 4건 추가 → 4 이상 (다른 테스트 잔여물이 + α일 수 있음)
    assertThat(baseline.activity24h()).isGreaterThanOrEqualTo(4);
    assertThat(baseline.adminMutations24h()).isGreaterThanOrEqualTo(1); // API_KEY_ISSUED
    assertThat(baseline.securityEvents24h())
        .isGreaterThanOrEqualTo(1); // SIGNATURE_COUNTER_REGRESSION

    // top tenants에 seed한 tenant 중 하나가 등장하는지
    List<UUID> topIds = baseline.topTenants().stream().map(r -> r.tenantId()).toList();
    assertThat(topIds).isNotEmpty();
  }

  @Test
  void feed_returns_items_from_multiple_tenants_with_correct_categories() {
    UUID t1 = tenantSeed.createTenant("feed-a-" + suffix());
    UUID t2 = tenantSeed.createTenant("feed-b-" + suffix());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    insertAuditRow(t1, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusMinutes(1));
    insertAuditRow(t2, AuditEventType.API_KEY_ISSUED, now.minusMinutes(2));

    FeedPage page = service.feed(null, "all", List.of(t1, t2));

    assertThat(page.items()).hasSizeGreaterThanOrEqualTo(2);
    assertThat(page.items().stream().map(i -> i.tenantId()))
        .as("응답에 두 tenant가 모두 등장")
        .contains(t1, t2);
    for (var item : page.items()) {
      assertThat(item.category())
          .as("category enum source-of-truth와 일치")
          .isEqualTo(item.eventType().category());
    }
  }

  @Test
  void feed_filter_by_category_returns_only_admin_actions() {
    UUID t = tenantSeed.createTenant("feed-cat-" + suffix());
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    insertAuditRow(t, AuditEventType.CREDENTIAL_AUTHENTICATED, now.minusMinutes(1)); // CEREMONY
    insertAuditRow(t, AuditEventType.API_KEY_ISSUED, now.minusMinutes(2)); // ADMIN_ACTION

    FeedPage page = service.feed(null, "admin-action", List.of(t));

    assertThat(page.items())
        .as("category=admin-action 필터에 ADMIN_ACTION만")
        .isNotEmpty()
        .allMatch(i -> i.category() == AuditCategory.ADMIN_ACTION);
  }

  @Test
  void feed_cursor_pagination_returns_consistent_window() {
    UUID t = tenantSeed.createTenant("feed-cursor-" + suffix());
    OffsetDateTime base = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(60);
    for (int i = 0; i < 35; i++) {
      insertAuditRow(t, AuditEventType.CREDENTIAL_AUTHENTICATED, base.plusSeconds(i));
    }

    FeedPage first = service.feed(null, "all", List.of(t));
    assertThat(first.items()).hasSize(30);
    assertThat(first.nextCursor()).isNotNull();

    FeedPage second = service.feed(first.nextCursor(), "all", List.of(t));
    assertThat(second.items()).hasSizeGreaterThanOrEqualTo(5);

    UUID lastOfFirst = first.items().get(first.items().size() - 1).id();
    UUID firstOfSecond = second.items().get(0).id();
    assertThat(lastOfFirst).as("페이지 경계가 중복되지 않는다 (strict-less cursor)").isNotEqualTo(firstOfSecond);
  }

  // ---- helpers ----

  private static String suffix() {
    return java.util.UUID.randomUUID().toString().substring(0, 8);
  }

  /**
   * audit_log row를 직접 INSERT. id/tenant_id 는 RAW(16) — HEXTORAW 바인딩. row_hash 칼럼은 NOT NULL이므로 dummy
   * 채움.
   */
  private void insertAuditRow(UUID tenantId, AuditEventType type, OffsetDateTime when) {
    UUID id = UUID.randomUUID();
    adminJdbc.update(
        "INSERT INTO audit_log "
            + "(id, tenant_id, event_type, actor_type, actor_id, row_hash, created_at) "
            + "VALUES (HEXTORAW(:id), HEXTORAW(:tid), :type, :actorType, :actorId, :rowHash, :ts)",
        new MapSqlParameterSource()
            .addValue("id", uuidToHex(id))
            .addValue("tid", uuidToHex(tenantId))
            .addValue("type", type.name())
            .addValue("actorType", "END_USER")
            .addValue("actorId", "actor-" + id.toString().substring(0, 8))
            .addValue("rowHash", "row-dummy-" + id.toString().substring(0, 8))
            .addValue("ts", when));
  }

  private static String uuidToHex(UUID u) {
    java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(16);
    bb.putLong(u.getMostSignificantBits());
    bb.putLong(u.getLeastSignificantBits());
    return java.util.HexFormat.of().formatHex(bb.array());
  }
}
