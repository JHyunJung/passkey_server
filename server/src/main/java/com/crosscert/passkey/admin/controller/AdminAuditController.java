package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.audit.domain.AuditEntry;
import com.crosscert.passkey.audit.repository.AuditEntryRepository;
import com.crosscert.passkey.common.response.ApiResponse;
import com.crosscert.passkey.common.response.PageResponse;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/tenants/{tenantId}/audit-logs")
@RequiredArgsConstructor
public class AdminAuditController {

  private final AuditEntryRepository repo;

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
  public ApiResponse<PageResponse<AuditView>> list(
      @PathVariable UUID tenantId,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int size) {
    AdminAuthz.requireTenantAccess(tenantId);
    Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
    Page<AuditEntry> result = repo.findAll(pageable);
    return ApiResponse.ok(PageResponse.from(result.map(AuditView::from)));
  }
}
