package com.crosscert.passkey.admin.controller;

import com.crosscert.passkey.admin.security.AdminAuthz;
import com.crosscert.passkey.admin.service.PlatformActivityService;
import com.crosscert.passkey.admin.service.PlatformActivityService.ActivitySummary;
import com.crosscert.passkey.admin.service.PlatformActivityService.FeedPage;
import com.crosscert.passkey.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cross-tenant Activity 페이지 데이터 endpoint. PLATFORM_OPERATOR 전용.
 *
 * <p>{@code @ConditionalOnProperty(passkey.admin.enabled=true)} — admin 콘솔이 배포된 인스턴스에서만 활성. {@link
 * AdminAuthz#requirePlatformOperator()}이 권한 게이트 단일 진입점.
 */
@RestController
@RequestMapping("/api/v1/admin/platform")
@RequiredArgsConstructor
@ConditionalOnProperty(name = "passkey.admin.enabled", havingValue = "true")
@Tag(name = "Admin · Platform · Activity", description = "Cross-tenant activity summary + feed.")
public class AdminPlatformActivityController {

  private final PlatformActivityService activityService;

  @GetMapping("/activity-summary")
  @Operation(
      summary = "Cross-tenant activity summary",
      description = "4개 메트릭(활동 24H, 운영 액션, 보안 이벤트, 평균 응답)과 활발한 tenant top-5를 한 응답으로 반환.")
  public ApiResponse<ActivitySummary> summary(
      @RequestParam(name = "window", defaultValue = "24h") String window) {
    AdminAuthz.requirePlatformOperator();
    return ApiResponse.ok(activityService.summary(window));
  }

  @GetMapping("/activity-feed")
  @Operation(
      summary = "Cross-tenant audit feed",
      description =
          "cursor 기반 페이지네이션. category ∈ {all, ceremony, admin-action, security-fail}. "
              + "tenantIds 미지정 시 전체.")
  public ApiResponse<FeedPage> feed(
      @RequestParam(name = "cursor", required = false) String cursor,
      @RequestParam(name = "category", defaultValue = "all") String category,
      @RequestParam(name = "tenantIds", required = false) List<UUID> tenantIds) {
    AdminAuthz.requirePlatformOperator();
    List<UUID> ids = tenantIds == null ? new ArrayList<>() : tenantIds;
    return ApiResponse.ok(activityService.feed(cursor, category, ids));
  }
}
