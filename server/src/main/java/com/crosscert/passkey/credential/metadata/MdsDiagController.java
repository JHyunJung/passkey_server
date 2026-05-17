package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.response.ApiResponse;
import com.webauthn4j.metadata.data.MetadataBLOB;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only diagnostics for the FIDO MDS BLOB cache. Exposed at {@code /_diag/mds-status}, which is
 * always permitAll in {@code AdminSecurityConfig.publicFilterChain} — production deployments must
 * block external access to {@code /_diag/**} at the load balancer.
 *
 * <p>If MDS is disabled, this endpoint still responds but reports {@code enabled=false}.
 */
@Slf4j
@RestController
@RequestMapping("/_diag")
@RequiredArgsConstructor
public class MdsDiagController {

  private final MdsProperties props;
  private final ObjectProvider<MdsBlobProvider> providerProvider;
  private final MeterRegistry meterRegistry;

  @GetMapping("/mds-status")
  public ApiResponse<Map<String, Object>> mdsStatus() {
    return ApiResponse.ok(buildStatusPayload(props, providerProvider.getIfAvailable()));
  }

  /**
   * Operator escape hatch — re-fetch the FIDO MDS BLOB immediately. Same logic as the daily
   * scheduler, but synchronous so a busy operator can confirm success in one round trip. {@code
   * /_diag/**} is always {@code permitAll}; production deployments must block external access at
   * the load balancer.
   */
  @PostMapping("/mds-refresh")
  public ApiResponse<Map<String, Object>> mdsRefresh() {
    return ApiResponse.ok(forceRefresh(props, providerProvider.getIfAvailable(), meterRegistry));
  }

  /**
   * Shared status builder — re-used by {@link com.crosscert.passkey.admin.controller
   * .AdminSystemController#mdsStatus()} so the two response shapes do not drift.
   */
  public static Map<String, Object> buildStatusPayload(
      MdsProperties props, MdsBlobProvider provider) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("enabled", props.isEnabled());
    body.put("blobUrl", props.getBlobUrl());
    body.put("refreshCron", props.getRefreshCron());
    if (provider == null) {
      body.put("status", "DISABLED");
      return body;
    }
    Instant lastFetched = provider.getLastFetched().get();
    MetadataBLOB blob = provider.getLastBlob().get();
    if (blob == null || lastFetched == null) {
      body.put("status", "NEVER_FETCHED");
      return body;
    }
    body.put("status", "READY");
    body.put("lastFetched", lastFetched.toString());
    body.put("entryCount", blob.getPayload().getEntries().size());
    body.put("nextUpdate", blob.getPayload().getNextUpdate());
    body.put("serialNumber", blob.getPayload().getNo());
    return body;
  }

  /**
   * Shared refresh implementation. {@link com.crosscert.passkey.admin.controller
   * .AdminSystemController} re-uses this to surface an authenticated equivalent under {@code
   * /api/v1/admin/system/mds/refresh}.
   */
  public static Map<String, Object> forceRefresh(
      MdsProperties props, MdsBlobProvider provider, MeterRegistry meterRegistry) {
    if (provider == null) {
      meterRegistry.counter("passkey.system.mds.refresh", "result", "disabled").increment();
      throw new BusinessException(ErrorCode.MDS_DISABLED);
    }
    try {
      provider.refresh();
      meterRegistry.counter("passkey.system.mds.refresh", "result", "success").increment();
      log.info("mds.refresh.manual.success");
      return buildStatusPayload(props, provider);
    } catch (RuntimeException e) {
      meterRegistry.counter("passkey.system.mds.refresh", "result", "fail").increment();
      log.error("mds.refresh.manual.failed reason={}", e.getMessage(), e);
      throw new BusinessException(ErrorCode.MDS_REFRESH_FAILED, e.getMessage(), e);
    }
  }
}
