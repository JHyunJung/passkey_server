package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.domain.AttestationConveyance;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.domain.UserVerificationPolicy;
import com.crosscert.passkey.credential.repository.TenantWebauthnConfigRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/webauthn-config")
@RequiredArgsConstructor
public class AdminWebauthnConfigController {

  private final TenantWebauthnConfigRepository repo;

  public record ConfigView(
      String rpId,
      String rpName,
      List<String> origins,
      int timeoutMs,
      String userVerification,
      String attestationConveyance) {

    static ConfigView from(TenantWebauthnConfig c) {
      return new ConfigView(
          c.getRpId(),
          c.getRpName(),
          c.originList(),
          c.getTimeoutMs(),
          c.getUserVerification().name(),
          c.getAttestationConveyance().name());
    }
  }

  public record UpsertRequest(
      @NotBlank String rpId,
      @NotBlank String rpName,
      @NotEmpty List<@NotBlank String> origins,
      @Positive int timeoutMs,
      @NotBlank String userVerification,
      @NotBlank String attestationConveyance) {}

  @GetMapping
  @Transactional(readOnly = true)
  public ApiResponse<ConfigView> get(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantWebauthnConfig c =
        repo.findByTenantId(tenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.WEBAUTHN_CONFIG_NOT_FOUND));
    return ApiResponse.ok(ConfigView.from(c));
  }

  @PutMapping
  @Transactional
  public ApiResponse<ConfigView> upsert(
      @PathVariable UUID tenantId, @Valid @RequestBody UpsertRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    UserVerificationPolicy uv = UserVerificationPolicy.valueOf(req.userVerification());
    AttestationConveyance ac = AttestationConveyance.valueOf(req.attestationConveyance());

    TenantWebauthnConfig cfg =
        repo.findByTenantId(tenantId)
            .orElseGet(
                () ->
                    repo.save(
                        TenantWebauthnConfig.create(
                            tenantId, req.rpId(), req.rpName(), req.origins())));
    cfg.update(req.rpId(), req.rpName(), req.origins(), req.timeoutMs(), uv, ac);
    return ApiResponse.ok(ConfigView.from(cfg));
  }
}
