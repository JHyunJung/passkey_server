package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.auth.apikey.cache.ApiKeyRevocationPublisher;
import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.auth.apikey.service.ApiKeyService;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/api-keys")
@RequiredArgsConstructor
public class AdminApiKeyController {

  private final ApiKeyService apiKeyService;
  private final ApiKeyRepository apiKeyRepo;
  private final AuditService auditService;
  private final ApiKeyRevocationPublisher revocationPublisher;

  public record IssueRequest(
      @NotBlank
          @jakarta.validation.constraints.Size(max = 100)
          @jakarta.validation.constraints.Pattern(
              regexp = "^[\\x20-\\x7E]+$",
              message = "name must be printable ASCII")
          String name) {}

  public record ApiKeyView(
      UUID id, String prefix, String name, String status, OffsetDateTime createdAt) {
    static ApiKeyView from(ApiKey k) {
      return new ApiKeyView(
          k.getId(), k.getPrefix(), k.getName(), k.getStatus().name(), k.getCreatedAt());
    }
  }

  public record IssuedKeyView(UUID id, String plaintext, String prefix, String name) {}

  @GetMapping
  @Transactional(readOnly = true)
  public ApiResponse<List<ApiKeyView>> list(@PathVariable UUID tenantId) {
    AdminAuthz.requireTenantAccess(tenantId);
    return ApiResponse.ok(
        apiKeyRepo.findAllByTenantId(tenantId).stream().map(ApiKeyView::from).toList());
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Transactional
  public ApiResponse<IssuedKeyView> issue(
      @PathVariable UUID tenantId, @Valid @RequestBody IssueRequest req) {
    AdminAuthz.requireTenantAccess(tenantId);
    ApiKeyService.IssuedKey issued = apiKeyService.issue(tenantId, req.name());
    auditService.append(
        AuditEventType.API_KEY_ISSUED,
        ActorType.ADMIN,
        AdminAuthz.currentPrincipal().adminId().toString(),
        "API_KEY",
        issued.id().toString(),
        Map.of("name", req.name()));
    return ApiResponse.ok(
        new IssuedKeyView(issued.id(), issued.plaintext(), issued.prefix(), req.name()));
  }

  @DeleteMapping("/{keyId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Transactional
  public ApiResponse<Void> revoke(@PathVariable UUID tenantId, @PathVariable UUID keyId) {
    AdminAuthz.requireTenantAccess(tenantId);
    ApiKey k =
        apiKeyRepo
            .findById(keyId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    if (!k.getTenantId().equals(tenantId)) {
      throw new BusinessException(ErrorCode.ADMIN_ROLE_FORBIDDEN);
    }
    k.revoke();
    auditService.append(
        AuditEventType.API_KEY_REVOKED,
        ActorType.ADMIN,
        AdminAuthz.currentPrincipal().adminId().toString(),
        "API_KEY",
        k.getId().toString(),
        Map.of());
    // Broadcast to peer instances so their Caffeine caches evict immediately.
    revocationPublisher.publish(k.getId());
    log.info(
        "admin.apikey.revoke adminId={} tenantId={} apiKeyId={}",
        AdminAuthz.currentPrincipal().adminId(),
        tenantId,
        k.getId());
    return ApiResponse.ok();
  }
}
