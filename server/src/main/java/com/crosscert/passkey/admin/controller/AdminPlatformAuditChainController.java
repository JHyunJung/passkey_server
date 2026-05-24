package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.PlatformAuditChainService;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.ChainStatus;
import com.crosscert.passkey.admin.service.PlatformAuditChainService.VerifyAllResult;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cross-tenant SHA-256 hash chain 무결성 모니터링 endpoint. PLATFORM_OPERATOR 전용.
 *
 * <p>{@link #status()}는 캐시된 결과를 빠르게 반환(TTL 60s). {@link #verifyAll()}은 모든 tenant를 직렬로 즉시 재검증 — 호출
 * 비용이 크니 사용자 액션(버튼)에만 노출.
 */
@RestController
@RequestMapping("/api/v1/admin/platform/audit-chain")
@RequiredArgsConstructor
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
@Tag(
    name = "Admin · Platform · Audit Chain",
    description = "Cross-tenant audit hash chain status + on-demand verify.")
public class AdminPlatformAuditChainController {

  private final PlatformAuditChainService chainService;

  @GetMapping("/status")
  @Operation(summary = "Audit chain status", description = "모든 tenant의 마지막 검증 결과 합산. 캐시 TTL 60s.")
  public ApiResponse<ChainStatus> status() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(chainService.status());
  }

  @PostMapping("/verify")
  @Operation(
      summary = "Verify all tenants now",
      description =
          "모든 ACTIVE tenant의 hash chain을 직렬 재검증 후 동기 응답. 실패한 tenant는 errors[]에 보고, "
              + "나머지 결과는 정상 포함.")
  public ApiResponse<VerifyAllResult> verifyAll() {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(chainService.verifyAll());
  }
}
