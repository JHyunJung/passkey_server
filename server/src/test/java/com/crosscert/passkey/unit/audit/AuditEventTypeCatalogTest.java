package com.crosscert.passkey.unit.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.audit.domain.AuditEventType;
import org.junit.jupiter.api.Test;

/**
 * Pins the new event types so any accidental rename / removal trips this test in CI before the
 * Admin SPA enum drifts out of sync.
 */
class AuditEventTypeCatalogTest {

  @Test
  void includes_p2_p3_events() {
    assertThat(AuditEventType.values())
        .contains(
            AuditEventType.REGISTRATION_OPTIONS_REQUESTED,
            AuditEventType.AUTHENTICATION_OPTIONS_REQUESTED,
            AuditEventType.ADMIN_USER_CREATED,
            AuditEventType.ADMIN_USER_DELETED,
            AuditEventType.ADMIN_USER_PASSWORD_RESET,
            AuditEventType.TENANT_SUSPENDED,
            AuditEventType.TENANT_ACTIVATED);
  }

  @Test
  void includes_credential_backup_state_changed() {
    assertThat(AuditEventType.values()).contains(AuditEventType.CREDENTIAL_BACKUP_STATE_CHANGED);
  }
}
