package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.domain.AuditEntry;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.repository.AuditEntryRepository;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.audit.service.AuditService.ChainVerification;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/audit-logs")
@RequiredArgsConstructor
@Tag(
    name = "Admin · Audit Logs",
    description = "Per-tenant audit log query + SHA-256 hash-chain verification.")
public class AdminAuditController {

  private final AuditEntryRepository repo;
  private final AuditService auditService;

  public record AuditView(
      UUID id,
      OffsetDateTime createdAt,
      String eventType,
      String actorType,
      String actorId,
      String subjectType,
      String subjectId,
      String payload) {
    static AuditView from(AuditEntry a) {
      return new AuditView(
          a.getId(),
          a.getCreatedAt(),
          a.getEventType().name(),
          a.getActorType().name(),
          a.getActorId(),
          a.getSubjectType(),
          a.getSubjectId(),
          a.getPayload());
    }
  }

  @GetMapping
  @Transactional(readOnly = true)
  @Operation(
      summary = "List audit log entries",
      description = "Paginated, newest first. Optional filter by event type.")
  public ApiResponse<PageResponse<AuditView>> list(
      @PathVariable UUID tenantId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size,
      @RequestParam(required = false) AuditEventType eventType) {
    AdminAuthz.requireTenantAccess(tenantId);
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    Page<AuditEntry> result =
        repo.findByTenantIdAndOptionalEventType(tenantId, eventType, pageable);
    return ApiResponse.ok(PageResponse.from(result.map(AuditView::from)));
  }

  /**
   * Replays the SHA-256 hash chain for the given tenant over an explicit time range and reports any
   * rows whose stored hash no longer matches the recomputed value. Used by compliance audits and by
   * the nightly self-check scheduler. Defaults to the last 24 hours when {@code from}/ {@code to}
   * are omitted.
   *
   * <p>Pass {@code failOnBroken=true} for compliance pipelines that need a non-200 response when
   * tampering is detected — the endpoint then returns {@code 500 D001 AUDIT_HASH_CHAIN_BROKEN} so a
   * CI/SOC alert can fire on HTTP status alone, without parsing the payload. The default {@code
   * false} preserves the previous behavior (200 + intact:false) for the admin SPA.
   */
  @GetMapping("/verify")
  @Operation(
      summary = "Verify audit hash chain",
      description =
          "Replay SHA-256 chain over [from, to). Set failOnBroken=true to receive 500 D001 instead of 200+intact:false.")
  public ApiResponse<ChainVerification> verify(
      @PathVariable UUID tenantId,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          OffsetDateTime from,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          OffsetDateTime to,
      @RequestParam(defaultValue = "false") boolean failOnBroken) {
    AdminAuthz.requireTenantAccess(tenantId);
    OffsetDateTime end = to != null ? to : OffsetDateTime.now(ZoneOffset.UTC);
    OffsetDateTime start = from != null ? from : end.minusDays(1);
    ChainVerification result = auditService.verifyIntegrity(tenantId, start, end);
    if (failOnBroken && !result.intact()) {
      throw new BusinessException(
          ErrorCode.AUDIT_HASH_CHAIN_BROKEN, "tampered rows: " + result.tamperedEntryIds().size());
    }
    return ApiResponse.ok(result);
  }
}
