package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.credential.domain.AttestationConveyance;
import com.crosscert.passkey.credential.domain.CredProtectPolicy;
import com.crosscert.passkey.credential.domain.ResidentKeyPolicy;
import com.crosscert.passkey.credential.domain.TenantWebauthnConfig;
import com.crosscert.passkey.credential.domain.UserVerificationPolicy;
import com.crosscert.passkey.credential.repository.TenantWebauthnConfigRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
@Tag(
    name = "Admin · WebAuthn Config",
    description = "Per-tenant rpId, origins, UV, attestation, resident key, credProtect.")
public class AdminWebauthnConfigController {

  private final TenantWebauthnConfigRepository repo;
  private final AuditService auditService;

  public record ConfigView(
      String rpId,
      String rpName,
      List<String> origins,
      int timeoutMs,
      String userVerification,
      String attestationConveyance,
      String residentKey,
      String credProtect) {

    static ConfigView from(TenantWebauthnConfig c) {
      return new ConfigView(
          c.getRpId(),
          c.getRpName(),
          c.originList(),
          c.getTimeoutMs(),
          c.getUserVerification().name(),
          c.getAttestationConveyance().name(),
          c.getResidentKey().name(),
          c.getCredProtect().name());
    }
  }

  public record UpsertRequest(
      @NotBlank String rpId,
      @NotBlank String rpName,
      @NotEmpty List<@NotBlank String> origins,
      @Positive int timeoutMs,
      @NotBlank String userVerification,
      @NotBlank String attestationConveyance,
      String residentKey,
      String credProtect) {}

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(summary = "Get WebAuthn config")
  public ApiResponse<ConfigView> get(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    TenantWebauthnConfig c =
        repo.findByTenantId(tenantId)
            .orElseThrow(() -> new BusinessException(ErrorCode.WEBAUTHN_CONFIG_NOT_FOUND));
    return ApiResponse.ok(ConfigView.from(c));
  }

  @PutMapping
  @Transactional
  @Operation(
      summary = "Update WebAuthn config",
      description = "Diff of changed fields is recorded to audit log as WEBAUTHN_CONFIG_UPDATED.")
  public ApiResponse<ConfigView> upsert(
      @PathVariable UUID tenantId, @Valid @RequestBody UpsertRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    UserVerificationPolicy uv = UserVerificationPolicy.valueOf(req.userVerification());
    AttestationConveyance ac = AttestationConveyance.valueOf(req.attestationConveyance());
    ResidentKeyPolicy rk =
        req.residentKey() == null
            ? ResidentKeyPolicy.PREFERRED
            : ResidentKeyPolicy.valueOf(req.residentKey());
    CredProtectPolicy cp =
        req.credProtect() == null
            ? CredProtectPolicy.NONE
            : CredProtectPolicy.valueOf(req.credProtect());

    TenantWebauthnConfig cfg =
        repo.findByTenantId(tenantId)
            .orElseGet(
                () ->
                    repo.save(
                        TenantWebauthnConfig.create(
                            tenantId, req.rpId(), req.rpName(), req.origins())));

    // Snapshot the before-state so the audit row can record the diff (P1-7 / forensics).
    ConfigView before = ConfigView.from(cfg);
    cfg.update(req.rpId(), req.rpName(), req.origins(), req.timeoutMs(), uv, ac, rk, cp);
    ConfigView after = ConfigView.from(cfg);

    auditService.append(
        AuditEventType.WEBAUTHN_CONFIG_UPDATED,
        ActorType.ADMIN,
        AdminAuthz.currentPrincipal().adminId().toString(),
        "WEBAUTHN_CONFIG",
        tenantId.toString(),
        diffPayload(before, after));

    return ApiResponse.ok(after);
  }

  private static Map<String, Object> diffPayload(ConfigView before, ConfigView after) {
    Map<String, Object> payload = new HashMap<>();
    putIfChanged(payload, "rpId", before.rpId(), after.rpId());
    putIfChanged(payload, "rpName", before.rpName(), after.rpName());
    putIfChanged(payload, "origins", before.origins(), after.origins());
    putIfChanged(payload, "timeoutMs", before.timeoutMs(), after.timeoutMs());
    putIfChanged(payload, "userVerification", before.userVerification(), after.userVerification());
    putIfChanged(
        payload,
        "attestationConveyance",
        before.attestationConveyance(),
        after.attestationConveyance());
    putIfChanged(payload, "residentKey", before.residentKey(), after.residentKey());
    putIfChanged(payload, "credProtect", before.credProtect(), after.credProtect());
    return payload;
  }

  private static void putIfChanged(Map<String, Object> payload, String key, Object a, Object b) {
    if (!Objects.equals(a, b)) {
      payload.put(key, Map.of("from", a == null ? "" : a, "to", b == null ? "" : b));
    }
  }
}
