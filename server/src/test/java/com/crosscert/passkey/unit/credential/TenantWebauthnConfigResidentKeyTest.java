package com.crosscert.passkey.unit.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.credential.domain.AttestationConveyance;
import com.crosscert.passkey.credential.domain.CredProtectPolicy;
import com.crosscert.passkey.credential.domain.ResidentKeyPolicy;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.domain.UserVerificationPolicy;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TenantWebauthnConfigResidentKeyTest {

  private static final UUID TENANT = UUID.randomUUID();

  @Test
  void create_defaults_residentKey_to_PREFERRED() {
    TenantWebauthnConfig cfg =
        TenantWebauthnConfig.create(
            TENANT, "card.co.kr", "Card", List.of("https://app.card.co.kr"));
    assertThat(cfg.getResidentKey()).isEqualTo(ResidentKeyPolicy.PREFERRED);
  }

  @Test
  void update_changes_residentKey() {
    TenantWebauthnConfig cfg =
        TenantWebauthnConfig.create(
            TENANT, "card.co.kr", "Card", List.of("https://app.card.co.kr"));
    cfg.update(
        "card.co.kr",
        "Card",
        List.of("https://app.card.co.kr"),
        60_000,
        UserVerificationPolicy.REQUIRED,
        AttestationConveyance.NONE,
        ResidentKeyPolicy.REQUIRED,
        CredProtectPolicy.NONE);
    assertThat(cfg.getResidentKey()).isEqualTo(ResidentKeyPolicy.REQUIRED);
    assertThat(cfg.getUserVerification()).isEqualTo(UserVerificationPolicy.REQUIRED);
  }
}
