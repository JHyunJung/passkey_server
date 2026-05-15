package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.common.response.ApiResponse;
import com.webauthn4j.metadata.data.MetadataBLOB;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only diagnostics for the FIDO MDS BLOB cache. Exposed at {@code /_diag/mds-status}, which is
 * always permitAll in {@code AdminSecurityConfig.publicFilterChain} — production deployments must
 * block external access to {@code /_diag/**} at the load balancer.
 *
 * <p>If MDS is disabled, this endpoint still responds but reports {@code enabled=false}.
 */
@RestController
@RequestMapping("/_diag")
@RequiredArgsConstructor
public class MdsDiagController {

  private final MdsProperties props;
  private final ObjectProvider<MdsBlobProvider> providerProvider;

  @GetMapping("/mds-status")
  public ApiResponse<Map<String, Object>> mdsStatus() {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("enabled", props.isEnabled());
    body.put("blobUrl", props.getBlobUrl());
    body.put("refreshCron", props.getRefreshCron());

    MdsBlobProvider provider = providerProvider.getIfAvailable();
    if (provider == null) {
      body.put("status", "DISABLED");
      return ApiResponse.ok(body);
    }

    Instant lastFetched = provider.getLastFetched().get();
    MetadataBLOB blob = provider.getLastBlob().get();
    if (blob == null || lastFetched == null) {
      body.put("status", "NEVER_FETCHED");
      return ApiResponse.ok(body);
    }
    body.put("status", "READY");
    body.put("lastFetched", lastFetched.toString());
    body.put("entryCount", blob.getPayload().getEntries().size());
    body.put("nextUpdate", blob.getPayload().getNextUpdate());
    body.put("serialNumber", blob.getPayload().getNo());
    return ApiResponse.ok(body);
  }
}
