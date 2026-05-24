package com.crosscert.passkey.unit.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.crosscert.passkey.audit.domain.ActorType;
import com.crosscert.passkey.audit.domain.AuditEntry;
import com.crosscert.passkey.audit.domain.AuditEventType;
import com.crosscert.passkey.audit.repository.AuditEntryRepository;
import com.crosscert.passkey.audit.service.AuditService;
import com.crosscert.passkey.audit.service.AuditService.ChainVerification;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Verifies the hash-chain replay logic. Skips Hibernate / advisory-lock side of the service — those
 * are exercised by integration tests. Hand-built entries reuse the same SHA-256 recipe as {@link
 * AuditService} so we test the inverse path correctly.
 */
@ExtendWith(MockitoExtension.class)
class AuditServiceVerifyIntegrityTest {

  @Mock private AuditEntryRepository repo;

  private AuditService service;

  @BeforeEach
  void setUp() {
    // verifyIntegrity exercises only the hash-chain replay — the async writer is never reached,
    // so a null dependency is sufficient here.
    service = new AuditService(repo, new ObjectMapper(), null, new SimpleMeterRegistry());
  }

  @Test
  void intact_chain_reports_no_tampered_entries() {
    UUID tenantId = UUID.fromString("11111111-1111-1111-1111-111111111111");
    AuditEntry first = buildEntry(tenantId, "", "{\"k\":1}", AuditEventType.CREDENTIAL_REGISTERED);
    AuditEntry second =
        buildEntry(
            tenantId, first.getRowHash(), "{\"k\":2}", AuditEventType.CREDENTIAL_AUTHENTICATED);
    when(repo.streamForTenantByTime(any(), any(), any())).thenReturn(Stream.of(first, second));

    ChainVerification result =
        service.verifyIntegrity(tenantId, OffsetDateTime.MIN, OffsetDateTime.MAX);

    assertThat(result.intact()).isTrue();
    assertThat(result.verifiedRows()).isEqualTo(2);
    assertThat(result.tamperedEntryIds()).isEmpty();
  }

  @Test
  void tampered_row_is_listed_in_result() {
    UUID tenantId = UUID.fromString("22222222-2222-2222-2222-222222222222");
    AuditEntry first = buildEntry(tenantId, "", "{\"k\":1}", AuditEventType.CREDENTIAL_REGISTERED);
    AuditEntry second =
        buildEntry(
            tenantId, first.getRowHash(), "{\"k\":2}", AuditEventType.CREDENTIAL_AUTHENTICATED);
    // Simulate a DBA editing the payload of the second row in place without recomputing rowHash.
    AuditEntry tampered =
        new AuditEntry(
            second.getId(),
            second.getCreatedAt(),
            tenantId,
            second.getEventType(),
            second.getActorType(),
            second.getActorId(),
            second.getSubjectType(),
            second.getSubjectId(),
            "{\"k\":\"forged\"}",
            first.getRowHash(),
            second.getRowHash());
    when(repo.streamForTenantByTime(any(), any(), any())).thenReturn(Stream.of(first, tampered));

    ChainVerification result =
        service.verifyIntegrity(tenantId, OffsetDateTime.MIN, OffsetDateTime.MAX);

    assertThat(result.intact()).isFalse();
    assertThat(result.tamperedEntryIds()).containsExactly(tampered.getId());
  }

  @Test
  void prev_hash_mismatch_is_caught() {
    UUID tenantId = UUID.fromString("33333333-3333-3333-3333-333333333333");
    AuditEntry first = buildEntry(tenantId, "", "{\"k\":1}", AuditEventType.CREDENTIAL_REGISTERED);
    // Build second with the right row hash but a forged prev_hash — chain replay should still
    // catch the discontinuity.
    String correctRowHash =
        sha256(
            first.getRowHash()
                + "|"
                + tenantId
                + "|"
                + AuditEventType.CREDENTIAL_AUTHENTICATED
                + "|"
                + "{\"k\":2}");
    AuditEntry forgedPrev =
        new AuditEntry(
            UUID.randomUUID(),
            OffsetDateTime.now(ZoneOffset.UTC),
            tenantId,
            AuditEventType.CREDENTIAL_AUTHENTICATED,
            ActorType.END_USER,
            "u",
            "S",
            "s",
            "{\"k\":2}",
            "deadbeef", // wrong prev_hash
            correctRowHash);
    when(repo.streamForTenantByTime(any(), any(), any())).thenReturn(Stream.of(first, forgedPrev));

    ChainVerification result =
        service.verifyIntegrity(tenantId, OffsetDateTime.MIN, OffsetDateTime.MAX);

    assertThat(result.tamperedEntryIds()).contains(forgedPrev.getId());
  }

  private AuditEntry buildEntry(
      UUID tenantId, String prevHash, String payload, AuditEventType eventType) {
    String rowHash = sha256(prevHash + "|" + tenantId + "|" + eventType + "|" + payload);
    return new AuditEntry(
        UUID.randomUUID(),
        OffsetDateTime.now(ZoneOffset.UTC),
        tenantId,
        eventType,
        ActorType.END_USER,
        "actor",
        "SUBJECT",
        "subject",
        payload,
        prevHash.isEmpty() ? null : prevHash,
        rowHash);
  }

  private static String sha256(String input) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  // Compile-time guard: this test depends on AuditService exposing verifyIntegrity. If the method
  // is renamed/removed, this will fail to compile rather than silently skip the contract.
  @SuppressWarnings("unused")
  private static final Method GUARD = lookup();

  private static Method lookup() {
    try {
      return AuditService.class.getMethod(
          "verifyIntegrity", UUID.class, OffsetDateTime.class, OffsetDateTime.class);
    } catch (NoSuchMethodException e) {
      throw new AssertionError(e);
    }
  }
}
