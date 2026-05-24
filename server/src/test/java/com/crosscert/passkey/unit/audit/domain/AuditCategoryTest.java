package com.crosscert.passkey.unit.audit.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.audit.domain.AuditCategory;
import com.crosscert.passkey.audit.domain.AuditEventType;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;

class AuditCategoryTest {

  @Test
  void every_event_type_maps_to_one_category() {
    for (AuditEventType e : AuditEventType.values()) {
      assertThat(e.category())
          .as("AuditEventType.%s 는 category()를 반환해야 한다 (null 금지)", e.name())
          .isNotNull();
    }
  }

  @Test
  void ceremony_events_are_grouped_correctly() {
    EnumSet<AuditEventType> expected =
        EnumSet.of(
            AuditEventType.REGISTRATION_OPTIONS_REQUESTED,
            AuditEventType.CREDENTIAL_REGISTERED,
            AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED,
            AuditEventType.CREDENTIAL_AUTHENTICATED,
            AuditEventType.CREDENTIAL_BACKUP_STATE_CHANGED);
    for (AuditEventType e : AuditEventType.values()) {
      if (e.category() == AuditCategory.CEREMONY) {
        assertThat(expected).contains(e);
      }
    }
    for (AuditEventType e : expected) {
      assertThat(e.category()).isEqualTo(AuditCategory.CEREMONY);
    }
  }

  @Test
  void admin_action_events_are_grouped_correctly() {
    EnumSet<AuditEventType> expected =
        EnumSet.of(
            AuditEventType.TENANT_CREATED,
            AuditEventType.TENANT_SUSPENDED,
            AuditEventType.TENANT_ACTIVATED,
            AuditEventType.API_KEY_ISSUED,
            AuditEventType.API_KEY_REVOKED,
            AuditEventType.WEBAUTHN_CONFIG_UPDATED,
            AuditEventType.ADMIN_USER_CREATED,
            AuditEventType.ADMIN_USER_DELETED,
            AuditEventType.ADMIN_USER_PASSWORD_RESET,
            AuditEventType.CREDENTIAL_REASSIGNED,
            AuditEventType.CREDENTIAL_RENAMED,
            AuditEventType.USER_FORCE_LOGOUT,
            AuditEventType.REFRESH_TOKEN_REVOKED);
    for (AuditEventType e : AuditEventType.values()) {
      if (e.category() == AuditCategory.ADMIN_ACTION) {
        assertThat(expected).contains(e);
      }
    }
    for (AuditEventType e : expected) {
      assertThat(e.category()).isEqualTo(AuditCategory.ADMIN_ACTION);
    }
  }

  @Test
  void security_fail_events_are_grouped_correctly() {
    EnumSet<AuditEventType> expected =
        EnumSet.of(
            AuditEventType.SIGNATURE_COUNTER_REGRESSION,
            AuditEventType.CREDENTIAL_AUTH_RATE_LIMIT,
            AuditEventType.ATTESTATION_TRUST_FAILED,
            AuditEventType.CREDENTIAL_AUTO_SUSPENDED,
            AuditEventType.CREDENTIAL_REVOKED,
            AuditEventType.CREDENTIAL_UNSUSPENDED);
    for (AuditEventType e : AuditEventType.values()) {
      if (e.category() == AuditCategory.SECURITY_FAIL) {
        assertThat(expected).contains(e);
      }
    }
    for (AuditEventType e : expected) {
      assertThat(e.category()).isEqualTo(AuditCategory.SECURITY_FAIL);
    }
  }
}
