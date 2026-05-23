# FIDO2 코어 Milestone B — Phase 3 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** FIDO MDS3 BLOB을 자체 파싱하는 `fido2.mds` 패키지와 cert-path 검증 인프라를 구축하고, packed-full(trust anchor)·apple·android-key attestation verifier를 자체 코어에 추가한다.

**Architecture:** MDS3 BLOB JWS 서명검증은 nimbus-jose-jwt, cert chain 검증은 JCA `CertPathValidator`(PKIX)에 위임하고, BLOB payload(JSON) 해석·AAGUID별 trust anchor 추출만 자체 `fido2.mds` 패키지에서 구현한다. `AttestationVerifier.verify()`에 nullable `MdsTrustAnchorSource` 파라미터를 추가해 — source가 있으면(strict) trust anchor 검증, 없으면(non-strict) Milestone A 동작. Phase 3는 strict 경로를 webauthn4j에서 전환하지 않는다(자체 코어 verifier를 추가만 함) — strict 전환·webauthn4j 제거는 Phase 4.

**Tech Stack:** Java 17, Spring Boot 3.5, nimbus-jose-jwt 9.40, JCA(`java.security.cert`), JUnit 5, AssertJ, BouncyCastle(`bcpkix-jdk18on` — testImplementation, cert fixture 생성), ArchUnit 1.3, Google Java Format(Spotless).

**범위 주의:** 이 계획은 Milestone B Phase 3만 다룬다. Phase 4(android-safetynet/fido-u2f/tpm + strict 경로 전환 + webauthn4j 완전 제거)는 별도 계획 `docs/superpowers/plans/<date>-fido2-core-milestone-b-phase4.md`로 작성한다. 설계 근거는 `docs/superpowers/specs/2026-05-23-fido2-core-milestone-b-design.md`.

**선행 상태:** Milestone A 완료. `fido2` 패키지에 cbor/cose/model/attestation(none·packed) + Registration/AuthenticationVerifier 존재. strict 경로는 `RegistrationService.verifyWithWebauthn4j()`가 webauthn4j 사용 — Phase 3에서는 그대로 둔다.

---

## 파일 구조

신규 생성 (`server/src/main/java/com/crosscert/passkey/fido2/mds/`):

| 파일 | 책임 |
|---|---|
| `MdsException.java` | MDS BLOB 파싱/검증 실패 (unchecked, 내부용 — `CborDecodeException`과 동급). |
| `StatusReport.java` | FIDO 인증 상태 enum + critical 판정. |
| `MetadataEntry.java` | AAGUID별 엔트리 — aaguid, trust anchor 인증서들, statusReports. |
| `MetadataBlob.java` | 파싱된 BLOB — entries + nextUpdate. `parse(jws, rootCa)` 정적 메서드. |
| `MdsTrustAnchorSource.java` | AAGUID → `Set<TrustAnchor>` 조회 + StatusReport 정책. attestation verifier가 사용. |

신규 생성 (`server/src/main/java/com/crosscert/passkey/fido2/attestation/`):

| 파일 | 책임 |
|---|---|
| `CertPathValidator.java` | x5c cert chain → MDS trust anchor PKIX 검증. JCA `java.security.cert.CertPathValidator` 래퍼. |
| `AppleAnonymousAttestationVerifier.java` | `fmt="apple"` 검증. nonce 확장 일치. |
| `AndroidKeyAttestationVerifier.java` | `fmt="android-key"` 검증. key attestation 확장. |

수정 (`server/src/main/java/com/crosscert/passkey/fido2/`):

| 파일 | 변경 |
|---|---|
| `attestation/AttestationVerifier.java` | `verify()`에 nullable `MdsTrustAnchorSource` 파라미터 추가, `permits`에 verifier 2종 추가. |
| `attestation/AttestationResult.java` | (변경 없음 — `trustPathPresent` 그대로 활용.) |
| `attestation/PackedAttestationVerifier.java` | `verifyFull`에 trust anchor 검증 추가 (source != null일 때). |
| `attestation/NoneAttestationVerifier.java` | `verify()` 시그니처에 새 파라미터 반영 (none은 사용 안 함). |
| `attestation/AttestationVerifiers.java` | 레지스트리에 `apple`·`android-key` 등록. |
| `RegistrationVerificationRequest.java` | nullable `MdsTrustAnchorSource` 필드 추가. |
| `RegistrationVerifier.java` | `MdsTrustAnchorSource`를 `AttestationVerifier.verify()`에 전달. |

수정 (`server/src/main/java/com/crosscert/passkey/credential/metadata/`):

| 파일 | 변경 |
|---|---|
| `MdsBlobProvider.java` | webauthn4j `FidoMDS3MetadataBLOBProvider` delegate → `RestClient` fetch + `MetadataBlob.parse()`. |
| `MdsTrustAnchorRepositoryConfig.java` | 제거 — 자체 `MdsTrustAnchorSource` 빈 wiring으로 대체 (신규 `MdsConfig.java`). |

테스트 (`server/src/test/java/com/crosscert/passkey/unit/fido2/`): 각 신규 클래스별 단위 테스트.

**Phase 3 종료 시점 상태:** MDS BLOB을 자체 파싱하고, packed-full/apple/android-key를 자체 검증. **strict 경로는 여전히 webauthn4j** — Phase 3는 `RegistrationService.verifyWithWebauthn4j()`를 건드리지 않는다. webauthn4j 의존성도 그대로. ArchUnit·`./gradlew check` 통과.

---

## Task 1: MDS BLOB 모델 — StatusReport / MetadataEntry / MdsException

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/mds/MdsException.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/mds/StatusReport.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/mds/MetadataEntry.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/mds/MetadataEntryTest.java`

- [ ] **Step 1: 실패 테스트 작성**

`MetadataEntryTest.java`:

```java
package com.crosscert.passkey.unit.fido2.mds;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MetadataEntryTest {

  @Test
  void entry_with_revoked_status_is_revoked() {
    MetadataEntry entry =
        new MetadataEntry(
            UUID.fromString("00000000-0000-0000-0000-000000000001"),
            List.of(),
            List.of(StatusReport.FIDO_CERTIFIED, StatusReport.REVOKED));
    assertThat(entry.isRevoked()).isTrue();
  }

  @Test
  void entry_with_attestation_key_compromise_is_revoked() {
    MetadataEntry entry =
        new MetadataEntry(
            UUID.randomUUID(), List.of(), List.of(StatusReport.ATTESTATION_KEY_COMPROMISE));
    assertThat(entry.isRevoked()).isTrue();
  }

  @Test
  void entry_with_only_certified_status_is_not_revoked() {
    MetadataEntry entry =
        new MetadataEntry(UUID.randomUUID(), List.of(), List.of(StatusReport.FIDO_CERTIFIED));
    assertThat(entry.isRevoked()).isFalse();
  }

  @Test
  void status_report_critical_classification() {
    assertThat(StatusReport.REVOKED.isCritical()).isTrue();
    assertThat(StatusReport.ATTESTATION_KEY_COMPROMISE.isCritical()).isTrue();
    assertThat(StatusReport.USER_VERIFICATION_BYPASS.isCritical()).isTrue();
    assertThat(StatusReport.FIDO_CERTIFIED.isCritical()).isFalse();
    assertThat(StatusReport.NOT_FIDO_CERTIFIED.isCritical()).isFalse();
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.mds.MetadataEntryTest"`
Expected: 컴파일 실패 — `MetadataEntry`, `StatusReport` 미존재.

- [ ] **Step 3: `MdsException` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/mds/MdsException.java`:

```java
package com.crosscert.passkey.fido2.mds;

/**
 * Thrown when a FIDO MDS3 metadata BLOB cannot be parsed or fails verification — a malformed JWS,
 * a bad payload, or a trust-chain failure on the BLOB's signing certificate. Unchecked; callers in
 * the {@code fido2} package translate it into a {@code Fido2VerificationException} or surface it as
 * an MDS-unavailable condition.
 */
public class MdsException extends RuntimeException {
  public MdsException(String message) {
    super(message);
  }

  public MdsException(String message, Throwable cause) {
    super(message, cause);
  }
}
```

- [ ] **Step 4: `StatusReport` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/mds/StatusReport.java`:

```java
package com.crosscert.passkey.fido2.mds;

/**
 * FIDO MDS3 authenticator status (a subset of the FIDO Metadata Service {@code AuthenticatorStatus}
 * registry). {@link #isCritical()} marks the statuses that must block registration: a revoked or
 * compromised authenticator must never be trusted regardless of tenant policy.
 *
 * <p>Unknown status strings from the BLOB map to {@link #UNKNOWN}, which is non-critical — an
 * unrecognized status does not by itself block registration (the BLOB may add new informational
 * statuses over time).
 */
public enum StatusReport {
  FIDO_CERTIFIED(false),
  FIDO_CERTIFIED_L1(false),
  FIDO_CERTIFIED_L2(false),
  FIDO_CERTIFIED_L3(false),
  NOT_FIDO_CERTIFIED(false),
  UPDATE_AVAILABLE(false),
  SELF_ASSERTION_SUBMITTED(false),
  REVOKED(true),
  ATTESTATION_KEY_COMPROMISE(true),
  USER_VERIFICATION_BYPASS(true),
  USER_KEY_REMOTE_COMPROMISE(true),
  USER_KEY_PHYSICAL_COMPROMISE(true),
  UNKNOWN(false);

  private final boolean critical;

  StatusReport(boolean critical) {
    this.critical = critical;
  }

  /** Whether this status must block registration (revoked / compromised classes). */
  public boolean isCritical() {
    return critical;
  }

  /** Map a FIDO MDS status string to a {@link StatusReport}; unrecognized strings become UNKNOWN. */
  public static StatusReport fromMdsString(String status) {
    if (status == null) {
      return UNKNOWN;
    }
    try {
      return valueOf(status.trim().toUpperCase(java.util.Locale.ROOT));
    } catch (IllegalArgumentException e) {
      return UNKNOWN;
    }
  }
}
```

- [ ] **Step 5: `MetadataEntry` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/mds/MetadataEntry.java`:

```java
package com.crosscert.passkey.fido2.mds;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

/**
 * One FIDO MDS3 metadata BLOB entry, keyed by authenticator AAGUID. {@code attestationRootCerts}
 * are the trust anchors an authenticator's attestation certificate chain must chain up to;
 * {@code statusReports} carries the authenticator's FIDO certification / revocation status.
 */
public record MetadataEntry(
    UUID aaguid, List<X509Certificate> attestationRootCerts, List<StatusReport> statusReports) {

  /**
   * Whether this authenticator has a critical (revoked / compromised) status and must be refused
   * regardless of tenant policy.
   */
  public boolean isRevoked() {
    return statusReports.stream().anyMatch(StatusReport::isCritical);
  }
}
```

- [ ] **Step 6: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.mds.MetadataEntryTest"`
Expected: PASS (4 tests).

- [ ] **Step 7: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/mds/ server/src/test/java/com/crosscert/passkey/unit/fido2/mds/
git commit -m "feat(fido2): MDS BLOB 모델 — StatusReport / MetadataEntry 추가

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: MetadataBlob — BLOB JWS 파싱

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/mds/MetadataBlob.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/mds/MetadataBlobTest.java`

MDS3 BLOB은 `x5c` 헤더에 cert chain을 담은 RS256 JWS다. nimbus-jose-jwt가 JWS 파싱·서명검증·x5c 추출을 하고, x5c 체인은 JCA로 FIDO Alliance Global Root CA까지 검증한다. payload(JSON)는 Jackson으로 파싱한다.

- [ ] **Step 1: 테스트 헬퍼 — MDS BLOB fixture 빌더 작성**

`server/src/test/java/com/crosscert/passkey/unit/fido2/mds/MdsTestFixtures.java` — BouncyCastle로 self-signed 루트 CA + BLOB 서명 cert를 만들고, nimbus로 BLOB JWS를 서명 생성한다:

```java
package com.crosscert.passkey.unit.fido2.mds;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test-only builder for FIDO MDS3 metadata BLOB fixtures. Produces a self-signed root CA, a BLOB
 * signing certificate chained to it, and a signed JWS BLOB — so the {@code fido2.mds} parser can
 * be exercised without reaching the real FIDO Alliance endpoint.
 */
public final class MdsTestFixtures {

  private MdsTestFixtures() {}

  /** A root CA keypair + certificate, plus a leaf signing keypair + certificate chained to it. */
  public record Pki(
      X509Certificate rootCa,
      X509Certificate signingCert,
      PrivateKey signingKey) {}

  /** Build a 2-cert PKI: self-signed root CA + a leaf signing cert issued by it. */
  public static Pki buildPki() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair rootPair = gen.generateKeyPair();
    KeyPair leafPair = gen.generateKeyPair();

    X509Certificate rootCa =
        selfSigned(rootPair, "CN=Test FIDO MDS Root", true);
    X509Certificate signingCert =
        issued(leafPair, "CN=Test MDS BLOB Signer", rootPair, "CN=Test FIDO MDS Root", false);
    return new Pki(rootCa, signingCert, leafPair.getPrivate());
  }

  /**
   * Sign {@code payloadJson} as an RS256 JWS with the {@code x5c} header carrying [signingCert,
   * rootCa] — the form a real FIDO MDS3 BLOB uses.
   */
  public static String signBlob(String payloadJson, Pki pki) throws Exception {
    JWSSigner signer = new RSASSASigner(pki.signingKey());
    JWSHeader header =
        new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(JOSEObjectType.JWT)
            .x509CertChain(
                List.of(
                    Base64.encode(pki.signingCert().getEncoded()),
                    Base64.encode(pki.rootCa().getEncoded())))
            .build();
    com.nimbusds.jose.Payload payload = new com.nimbusds.jose.Payload(payloadJson);
    com.nimbusds.jose.JWSObject jws = new com.nimbusds.jose.JWSObject(header, payload);
    jws.sign(signer);
    return jws.serialize();
  }

  private static X509Certificate selfSigned(KeyPair pair, String dn, boolean ca) throws Exception {
    return issued(pair, dn, pair, dn, ca);
  }

  private static X509Certificate issued(
      KeyPair subjectPair, String subjectDn, KeyPair issuerPair, String issuerDn, boolean ca)
      throws Exception {
    Instant now = Instant.now();
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn),
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            new X500Name(subjectDn),
            subjectPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(issuerPair.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }
}
```

- [ ] **Step 2: `MetadataBlobTest` 작성**

`server/src/test/java/com/crosscert/passkey/unit/fido2/mds/MetadataBlobTest.java`:

```java
package com.crosscert.passkey.unit.fido2.mds;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.mds.MdsException;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MetadataBlobTest {

  // A minimal MDS3 payload: one entry with an AAGUID and a FIDO_CERTIFIED status.
  private static final String SAMPLE_PAYLOAD =
      "{\"no\":42,\"nextUpdate\":\"2099-01-01\",\"entries\":["
          + "{\"aaguid\":\"00000000-0000-0000-0000-000000000001\","
          + "\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\"}],"
          + "\"metadataStatement\":{\"attestationRootCertificates\":[]}}"
          + "]}";

  @Test
  void parses_a_valid_signed_blob() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob(SAMPLE_PAYLOAD, pki);

    MetadataBlob blob = MetadataBlob.parse(jws, pki.rootCa());
    assertThat(blob.entries()).hasSize(1);
    MetadataEntry entry = blob.entries().get(0);
    assertThat(entry.aaguid())
        .isEqualTo(UUID.fromString("00000000-0000-0000-0000-000000000001"));
    assertThat(entry.isRevoked()).isFalse();
  }

  @Test
  void rejects_blob_signed_by_untrusted_root() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    MdsTestFixtures.Pki otherPki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob(SAMPLE_PAYLOAD, pki);

    // Verify against a different root CA — the x5c chain does not chain to it.
    assertThatThrownBy(() -> MetadataBlob.parse(jws, otherPki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_blob_with_tampered_payload() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String jws = MdsTestFixtures.signBlob(SAMPLE_PAYLOAD, pki);
    // Corrupt the payload segment (middle of the three dot-separated JWS parts).
    String[] parts = jws.split("\\.");
    String tampered = parts[0] + "." + parts[1] + "x." + parts[2];

    assertThatThrownBy(() -> MetadataBlob.parse(tampered, pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }

  @Test
  void rejects_malformed_jws() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    assertThatThrownBy(() -> MetadataBlob.parse("not-a-jws", pki.rootCa()))
        .isInstanceOf(MdsException.class);
  }
}
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.mds.MetadataBlobTest"`
Expected: 컴파일 실패 — `MetadataBlob` 미존재.

- [ ] **Step 4: `MetadataBlob` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/mds/MetadataBlob.java`:

```java
package com.crosscert.passkey.fido2.mds;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * A parsed, signature-verified FIDO MDS3 metadata BLOB. {@link #parse(String, X509Certificate)}
 * verifies the JWS signature using the {@code x5c} header chain, validates that chain up to the
 * supplied FIDO Alliance root CA via PKIX, then decodes the JSON payload into {@link
 * MetadataEntry} records. JWS parsing/verification uses nimbus-jose-jwt; chain validation uses the
 * JDK's {@code CertPathValidator}. Any failure throws {@link MdsException}.
 */
public final class MetadataBlob {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final List<MetadataEntry> entries;
  private final String nextUpdate;

  private MetadataBlob(List<MetadataEntry> entries, String nextUpdate) {
    this.entries = entries;
    this.nextUpdate = nextUpdate;
  }

  /** The MDS entries, one per authenticator AAGUID. */
  public List<MetadataEntry> entries() {
    return entries;
  }

  /** The BLOB's declared {@code nextUpdate} date string (informational). */
  public String nextUpdate() {
    return nextUpdate;
  }

  /**
   * Parse and verify a FIDO MDS3 BLOB. {@code jws} is the raw JWS compact serialization;
   * {@code fidoRootCa} is the FIDO Alliance Global Root CA the BLOB's signing chain must chain to.
   */
  public static MetadataBlob parse(String jws, X509Certificate fidoRootCa) {
    JWSObject jwsObject;
    try {
      jwsObject = JWSObject.parse(jws);
    } catch (Exception e) {
      throw new MdsException("MDS BLOB is not a valid JWS: " + e.getMessage(), e);
    }
    List<X509Certificate> chain = extractX5cChain(jwsObject);
    verifyChainToRoot(chain, fidoRootCa);
    verifyJwsSignature(jwsObject, chain.get(0));

    String payloadJson = jwsObject.getPayload().toString();
    return decodePayload(payloadJson);
  }

  private static List<X509Certificate> extractX5cChain(JWSObject jwsObject) {
    List<Base64> x5c = jwsObject.getHeader().getX509CertChain();
    if (x5c == null || x5c.isEmpty()) {
      throw new MdsException("MDS BLOB JWS header has no x5c certificate chain");
    }
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<X509Certificate> chain = new ArrayList<>(x5c.size());
      for (Base64 der : x5c) {
        chain.add(
            (X509Certificate)
                cf.generateCertificate(new ByteArrayInputStream(der.decode())));
      }
      return chain;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB x5c chain is unparseable: " + e.getMessage(), e);
    }
  }

  private static void verifyChainToRoot(List<X509Certificate> chain, X509Certificate fidoRootCa) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      // The cert path excludes the trust anchor itself — drop the last cert if it equals the root.
      List<X509Certificate> pathCerts = new ArrayList<>(chain);
      if (!pathCerts.isEmpty()
          && pathCerts.get(pathCerts.size() - 1).equals(fidoRootCa)) {
        pathCerts.remove(pathCerts.size() - 1);
      }
      if (pathCerts.isEmpty()) {
        throw new MdsException("MDS BLOB x5c chain has no leaf after removing the root");
      }
      CertPath certPath = cf.generateCertPath(pathCerts);
      PKIXParameters params =
          new PKIXParameters(Set.of(new TrustAnchor(fidoRootCa, null)));
      params.setRevocationEnabled(false); // BLOB freshness is governed by nextUpdate, not CRL/OCSP
      CertPathValidator.getInstance("PKIX").validate(certPath, params);
    } catch (MdsException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException(
          "MDS BLOB signing chain does not validate to the FIDO root CA: " + e.getMessage(), e);
    }
  }

  private static void verifyJwsSignature(JWSObject jwsObject, X509Certificate signingCert) {
    try {
      if (!(signingCert.getPublicKey() instanceof RSAPublicKey rsaKey)) {
        throw new MdsException("MDS BLOB signing certificate is not RSA");
      }
      JWSVerifier verifier = new RSASSAVerifier(rsaKey);
      if (!jwsObject.verify(verifier)) {
        throw new MdsException("MDS BLOB JWS signature is invalid");
      }
    } catch (MdsException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB JWS signature verification failed: " + e.getMessage(), e);
    }
  }

  private static MetadataBlob decodePayload(String payloadJson) {
    try {
      JsonNode root = MAPPER.readTree(payloadJson);
      JsonNode entriesNode = root.get("entries");
      if (entriesNode == null || !entriesNode.isArray()) {
        throw new MdsException("MDS BLOB payload has no entries array");
      }
      List<MetadataEntry> entries = new ArrayList<>();
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      for (JsonNode entryNode : entriesNode) {
        entries.add(decodeEntry(entryNode, cf));
      }
      JsonNode nextUpdate = root.get("nextUpdate");
      return new MetadataBlob(
          Collections.unmodifiableList(entries),
          nextUpdate == null ? null : nextUpdate.asText());
    } catch (MdsException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB payload is not valid JSON: " + e.getMessage(), e);
    }
  }

  private static MetadataEntry decodeEntry(JsonNode entryNode, CertificateFactory cf)
      throws Exception {
    JsonNode aaguidNode = entryNode.get("aaguid");
    UUID aaguid = aaguidNode == null ? null : UUID.fromString(aaguidNode.asText());

    List<StatusReport> statuses = new ArrayList<>();
    JsonNode statusReports = entryNode.get("statusReports");
    if (statusReports != null && statusReports.isArray()) {
      for (JsonNode sr : statusReports) {
        JsonNode status = sr.get("status");
        if (status != null) {
          statuses.add(StatusReport.fromMdsString(status.asText()));
        }
      }
    }

    List<X509Certificate> rootCerts = new ArrayList<>();
    JsonNode statement = entryNode.get("metadataStatement");
    if (statement != null) {
      JsonNode roots = statement.get("attestationRootCertificates");
      if (roots != null && roots.isArray()) {
        for (JsonNode certB64 : roots) {
          byte[] der = java.util.Base64.getDecoder().decode(certB64.asText());
          rootCerts.add(
              (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
      }
    }
    return new MetadataEntry(aaguid, rootCerts, statuses);
  }
}
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.mds.MetadataBlobTest"`
Expected: PASS (4 tests).

테스트가 실패하면 — nimbus JWS API 또는 PKIX 검증 로직의 버그를 추적해 수정하세요. fixture 빌더(`MdsTestFixtures`)와 테스트 코드는 임의로 바꾸지 마세요.

- [ ] **Step 6: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/mds/ server/src/test/java/com/crosscert/passkey/unit/fido2/mds/
git commit -m "feat(fido2): MetadataBlob — MDS3 BLOB JWS 파싱·서명검증 추가

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: MdsTrustAnchorSource — AAGUID별 trust anchor 조회

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/mds/MdsTrustAnchorSource.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/mds/MdsTrustAnchorSourceTest.java`

attestation verifier가 AAGUID로 trust anchor를 조회하고 revoked 여부를 확인하는 진입점이다. `MetadataBlob`을 받아 AAGUID → entry 맵을 만든다.

- [ ] **Step 1: 테스트 작성**

`MdsTrustAnchorSourceTest.java`:

```java
package com.crosscert.passkey.unit.fido2.mds;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.mds.StatusReport;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MdsTrustAnchorSourceTest {

  private static final UUID AAGUID_A = UUID.fromString("00000000-0000-0000-0000-00000000000a");
  private static final UUID AAGUID_REVOKED =
      UUID.fromString("00000000-0000-0000-0000-0000000000bb");
  private static final UUID AAGUID_UNKNOWN =
      UUID.fromString("00000000-0000-0000-0000-0000000000cc");

  private static MdsTrustAnchorSource source() {
    return new MdsTrustAnchorSource(
        List.of(
            new MetadataEntry(AAGUID_A, List.of(), List.of(StatusReport.FIDO_CERTIFIED)),
            new MetadataEntry(AAGUID_REVOKED, List.of(), List.of(StatusReport.REVOKED))));
  }

  @Test
  void finds_entry_by_aaguid() {
    assertThat(source().findEntry(AAGUID_A)).isPresent();
  }

  @Test
  void returns_empty_for_unknown_aaguid() {
    assertThat(source().findEntry(AAGUID_UNKNOWN)).isEmpty();
  }

  @Test
  void reports_revoked_authenticator() {
    assertThat(source().findEntry(AAGUID_REVOKED)).get().extracting(MetadataEntry::isRevoked)
        .isEqualTo(true);
  }

  @Test
  void null_aaguid_returns_empty() {
    assertThat(source().findEntry(null)).isEmpty();
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.mds.MdsTrustAnchorSourceTest"`
Expected: 컴파일 실패 — `MdsTrustAnchorSource` 미존재.

- [ ] **Step 3: `MdsTrustAnchorSource` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/mds/MdsTrustAnchorSource.java`:

```java
package com.crosscert.passkey.fido2.mds;

import java.security.cert.TrustAnchor;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Resolves FIDO MDS3 metadata by authenticator AAGUID. An attestation verifier in strict mode
 * looks up the {@link MetadataEntry} for the credential's AAGUID to (a) obtain the attestation
 * certificate trust anchors and (b) check the authenticator's revocation status.
 *
 * <p>Immutable — built from one parsed {@link MetadataBlob}'s entries. {@code MdsBlobProvider}
 * swaps in a fresh instance on each successful BLOB refresh.
 */
public final class MdsTrustAnchorSource {

  private final Map<UUID, MetadataEntry> byAaguid;

  public MdsTrustAnchorSource(List<MetadataEntry> entries) {
    Map<UUID, MetadataEntry> map = new HashMap<>();
    for (MetadataEntry entry : entries) {
      if (entry.aaguid() != null) {
        map.put(entry.aaguid(), entry);
      }
    }
    this.byAaguid = Map.copyOf(map);
  }

  /** Find the MDS entry for {@code aaguid}, or empty when the AAGUID is null or not in the BLOB. */
  public Optional<MetadataEntry> findEntry(UUID aaguid) {
    if (aaguid == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(byAaguid.get(aaguid));
  }

  /** The attestation-root trust anchors for {@code aaguid}, empty when the AAGUID is unknown. */
  public Set<TrustAnchor> trustAnchors(UUID aaguid) {
    return findEntry(aaguid)
        .map(
            e ->
                e.attestationRootCerts().stream()
                    .map(c -> new TrustAnchor(c, null))
                    .collect(Collectors.toSet()))
        .orElseGet(Set::of);
  }
}
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.mds.MdsTrustAnchorSourceTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/mds/ server/src/test/java/com/crosscert/passkey/unit/fido2/mds/
git commit -m "feat(fido2): MdsTrustAnchorSource — AAGUID별 trust anchor 조회 추가

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: AttestationCertPathValidator — x5c 체인 PKIX 검증

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationCertPathValidator.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AttestationCertPathValidatorTest.java`

attestation cert 체인을 MDS trust anchor까지 JCA PKIX로 검증한다. `Task 2`의 `MetadataBlob`이 BLOB 자체 서명 체인을 검증한 것과 동일 패턴 — 재사용 가능한 형태로 분리한다.

- [ ] **Step 1: 테스트 작성**

`AttestationCertPathValidatorTest.java`:

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.attestation.AttestationCertPathValidator;
import com.crosscert.passkey.unit.fido2.mds.MdsTestFixtures;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AttestationCertPathValidatorTest {

  @Test
  void validates_chain_to_trusted_root() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    // leaf (signingCert) is issued by rootCa — chain [leaf] validates against root anchor.
    boolean ok =
        AttestationCertPathValidator.validates(
            List.of(pki.signingCert()), Set.of(new TrustAnchor(pki.rootCa(), null)));
    assertThat(ok).isTrue();
  }

  @Test
  void rejects_chain_against_wrong_root() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    MdsTestFixtures.Pki other = MdsTestFixtures.buildPki();
    boolean ok =
        AttestationCertPathValidator.validates(
            List.of(pki.signingCert()), Set.of(new TrustAnchor(other.rootCa(), null)));
    assertThat(ok).isFalse();
  }

  @Test
  void rejects_empty_anchor_set() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    boolean ok =
        AttestationCertPathValidator.validates(List.of(pki.signingCert()), Set.of());
    assertThat(ok).isFalse();
  }

  @Test
  void rejects_empty_chain() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    boolean ok =
        AttestationCertPathValidator.validates(
            List.<X509Certificate>of(), Set.of(new TrustAnchor(pki.rootCa(), null)));
    assertThat(ok).isFalse();
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AttestationCertPathValidatorTest"`
Expected: 컴파일 실패 — `AttestationCertPathValidator` 미존재.

- [ ] **Step 3: `AttestationCertPathValidator` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationCertPathValidator.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * Validates an attestation certificate chain up to a set of trust anchors using the JDK's PKIX
 * {@code CertPathValidator}. Used by strict-mode attestation verifiers to confirm an
 * authenticator's attestation certificate chains to an MDS-sourced root.
 *
 * <p>Revocation checking (CRL / OCSP) is disabled: FIDO MDS metadata freshness — not certificate
 * revocation lists — governs authenticator trust, and attestation certificates are typically
 * long-lived batch certificates without CRL distribution points.
 */
public final class AttestationCertPathValidator {

  private AttestationCertPathValidator() {}

  /**
   * Returns {@code true} when {@code chain} (leaf-first, excluding the trust anchor) validates to
   * one of {@code trustAnchors}. Returns {@code false} — never throws — when the chain is empty,
   * the anchor set is empty, or PKIX validation fails for any reason.
   */
  public static boolean validates(List<X509Certificate> chain, Set<TrustAnchor> trustAnchors) {
    if (chain.isEmpty() || trustAnchors.isEmpty()) {
      return false;
    }
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      CertPath certPath = cf.generateCertPath(chain);
      PKIXParameters params = new PKIXParameters(trustAnchors);
      params.setRevocationEnabled(false);
      CertPathValidator.getInstance("PKIX").validate(certPath, params);
      return true;
    } catch (Exception e) {
      // Any PKIX failure — untrusted root, expired cert, broken chain — means "not trusted".
      return false;
    }
  }
}
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AttestationCertPathValidatorTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationCertPathValidator.java server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AttestationCertPathValidatorTest.java
git commit -m "feat(fido2): AttestationCertPathValidator — x5c 체인 PKIX 검증 추가

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: AttestationVerifier 인터페이스 확장 — MdsTrustAnchorSource 파라미터

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/NoneAttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/PackedAttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java`
- Modify: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AttestationVerifierTest.java`

이 Task는 인터페이스 시그니처 변경이라 — 컴파일이 깨졌다가 한 번에 복구된다. verifier 구현·테스트를 모두 새 시그니처에 맞춘다.

- [ ] **Step 1: `AttestationVerifier` 인터페이스에 파라미터 추가**

`AttestationVerifier.java`의 `verify` 메서드와 javadoc·permits를 다음으로 교체:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.model.AttestationObject;

/**
 * Verifies one attestation statement format (WebAuthn L3 §8). Each implementation handles a single
 * {@code fmt} value. Milestone A shipped {@code none} and {@code packed}; Milestone B Phase 3 adds
 * {@code apple} and {@code android-key}.
 *
 * <p>{@code trustAnchors} carries strict-mode policy: when non-null the verifier validates the
 * attestation certificate chain against MDS-sourced trust anchors and rejects revoked
 * authenticators; when null (non-strict) only the format's structural / signature checks run.
 * Sealed so the supported set is explicit.
 */
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier,
        PackedAttestationVerifier,
        AppleAnonymousAttestationVerifier,
        AndroidKeyAttestationVerifier {

  /** The {@code fmt} string this verifier handles. */
  String format();

  /**
   * Verify the attestation statement of {@code attestationObject} against {@code clientDataHash}
   * (SHA-256 of clientDataJSON). When {@code trustAnchors} is non-null, additionally validate the
   * attestation certificate chain to an MDS trust anchor and reject revoked authenticators. Throws
   * {@link Fido2VerificationException} on any failure.
   */
  AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException;
}
```

- [ ] **Step 2: `NoneAttestationVerifier` 시그니처 갱신**

`NoneAttestationVerifier.java`의 `verify` 메서드 시그니처에 파라미터를 추가한다. `none`은 trust anchor를 쓰지 않으므로 파라미터는 무시한다. 메서드 전체를 다음으로 교체:

```java
  @Override
  public AttestationResult verify(
      AttestationObject attestationObject,
      byte[] clientDataHash,
      com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    // none attestation carries no certificate — trustAnchors is not applicable.
    if (!attestationObject.attestationStatement().isEmpty()) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "none attestation must have an empty statement");
    }
    return new AttestationResult("none", false);
  }
```

- [ ] **Step 3: `PackedAttestationVerifier` 시그니처 갱신 + trust anchor 검증 추가**

`PackedAttestationVerifier.java`의 `verify` 메서드 시그니처에 `MdsTrustAnchorSource trustAnchors` 파라미터를 추가하고, `verifyFull` 호출 시 그것을 전달한다. `verify` 메서드의 시그니처 라인과 `verifyFull`/`verifySelf` 호출 분기를 다음으로 교체:

```java
  @Override
  public AttestationResult verify(
      AttestationObject attestationObject,
      byte[] clientDataHash,
      com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    Map<?, ?> attStmt = attestationObject.attestationStatement();

    Object sigObj = attStmt.get("sig");
    if (!(sigObj instanceof byte[] signature)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed attestation missing sig");
    }
    Object algObj = attStmt.get("alg");
    if (!(algObj instanceof Long algValue)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed attestation missing alg");
    }

    AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
    if (acd == null) {
      throw new Fido2VerificationException(
          FailureReason.NO_ATTESTED_CREDENTIAL, "attestation has no attested credential data");
    }

    ByteArrayOutputStream signedDataOut = new ByteArrayOutputStream();
    signedDataOut.writeBytes(attestationObject.authenticatorData().rawBytes());
    signedDataOut.writeBytes(clientDataHash);
    byte[] signedData = signedDataOut.toByteArray();

    Object x5cObj = attStmt.get("x5c");
    if (x5cObj != null) {
      return verifyFull(x5cObj, acd, algValue, signedData, signature, trustAnchors);
    } else {
      return verifySelf(acd, algValue, signedData, signature);
    }
  }
```

그리고 `verifyFull` 메서드 시그니처에 `MdsTrustAnchorSource trustAnchors` 파라미터를 추가하고, §8.2.1 검증(`verifyAttestationCertificateRequirements`) 직후·서명 검증 직후에 trust anchor 검증을 추가한다. `verifyFull` 메서드를 다음으로 교체:

```java
  /**
   * Full attestation (x5c present): validate the attestation certificate's WebAuthn L3 §8.2.1
   * requirements, verify the attestation signature with the certificate's public key, and — when
   * {@code trustAnchors} is non-null (strict mode) — validate the certificate chain to an MDS
   * trust anchor and reject revoked authenticators. When {@code trustAnchors} is null the chain
   * trust path is not validated (non-strict — matches webauthn4j's non-strict manager).
   */
  private static AttestationResult verifyFull(
      Object x5cObj,
      AttestedCredentialData acd,
      long algValue,
      byte[] signedData,
      byte[] signature,
      com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      if (!(x5cObj instanceof List<?> x5cList) || x5cList.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "packed x5c must be a non-empty array");
      }
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      java.util.List<X509Certificate> chain = new java.util.ArrayList<>();
      for (Object certObj : x5cList) {
        if (!(certObj instanceof byte[] certDer)) {
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID,
              "packed x5c element must be a DER-encoded certificate");
        }
        chain.add(
            (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer)));
      }
      X509Certificate cert = chain.get(0);

      // WebAuthn L3 §8.2.1: validate the attestation certificate's integrity requirements.
      verifyAttestationCertificateRequirements(cert, acd);

      // Verify the signature using the attestation cert's public key.
      String jcaAlg = jcaAlgorithmForCoseAlg(algValue);
      java.security.Signature verifier = java.security.Signature.getInstance(jcaAlg);
      verifier.initVerify(cert.getPublicKey());
      verifier.update(signedData);
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "packed full attestation signature invalid against attestation cert");
      }

      // Strict mode (trustAnchors != null): validate the chain to an MDS trust anchor and reject
      // revoked authenticators. Non-strict (null): the chain trust path is not validated.
      if (trustAnchors != null) {
        verifyTrustAnchor(chain, acd, trustAnchors);
      }
      return new AttestationResult("packed", true);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (CertificateException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed x5c certificate parse failed: " + e.getMessage());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed full attestation algorithm/key error: " + e.getMessage());
    } catch (SignatureException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed full attestation malformed signature: " + e.getMessage());
    } catch (RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "packed full attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Strict-mode trust validation: reject a revoked authenticator, then validate the attestation
   * certificate chain to one of the MDS trust anchors registered for the credential's AAGUID.
   */
  private static void verifyTrustAnchor(
      java.util.List<X509Certificate> chain,
      AttestedCredentialData acd,
      com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    java.util.UUID aaguid = aaguidOf(acd);
    java.util.Optional<com.crosscert.passkey.fido2.mds.MetadataEntry> entry =
        trustAnchors.findEntry(aaguid);
    if (entry.isEmpty()) {
      throw new Fido2VerificationException(
          FailureReason.MDS_TRUST_FAILED,
          "no MDS entry for AAGUID " + aaguid + " — authenticator not in metadata");
    }
    if (entry.get().isRevoked()) {
      throw new Fido2VerificationException(
          FailureReason.AUTHENTICATOR_REVOKED,
          "authenticator AAGUID " + aaguid + " is revoked or compromised per MDS");
    }
    if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
      throw new Fido2VerificationException(
          FailureReason.TRUST_PATH_INVALID,
          "attestation certificate chain does not validate to an MDS trust anchor");
    }
  }

  /** Decode the 16-byte AAGUID of {@code acd} into a {@link java.util.UUID}. */
  private static java.util.UUID aaguidOf(AttestedCredentialData acd) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(acd.aaguid());
    return new java.util.UUID(buf.getLong(), buf.getLong());
  }
```

> **참고:** `FailureReason.MDS_TRUST_FAILED`·`AUTHENTICATOR_REVOKED`·`TRUST_PATH_INVALID`는 Task 6에서 `Fido2VerificationException.FailureReason` enum에 추가한다 — 이 Task의 컴파일은 Task 6 enum 추가 후 통과한다. **Task 6을 먼저 하거나, 이 Task에서 enum 값도 함께 추가하라.** (실행 편의상 Step 4에서 enum을 먼저 추가한다.)

- [ ] **Step 4: `Fido2VerificationException.FailureReason`에 enum 값 추가**

`server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java`의 `FailureReason` enum에 — 기존 마지막 값 `SIGNATURE_INVALID` 뒤에 3개를 추가한다:

```java
    SIGNATURE_INVALID,
    /** The attestation certificate chain does not validate to an MDS trust anchor. */
    TRUST_PATH_INVALID,
    /** No MDS metadata entry exists for the authenticator's AAGUID. */
    MDS_TRUST_FAILED,
    /** The authenticator is revoked or compromised per its MDS status report. */
    AUTHENTICATOR_REVOKED
```

(기존 `SIGNATURE_INVALID` 뒤의 `}` 전에 위 3개를 삽입. `SIGNATURE_INVALID` 줄 끝 쉼표 확인.)

- [ ] **Step 5: `AttestationVerifiers` 레지스트리 — 시그니처는 그대로, 등록은 Task 7에서**

`AttestationVerifiers.java`는 이 Task에서 변경하지 않는다 (apple/android-key verifier가 아직 없으므로). `forFormat`은 verifier 인스턴스를 반환만 하므로 시그니처 변경 영향 없음.

- [ ] **Step 6: 기존 `AttestationVerifierTest` 호출부 갱신**

`AttestationVerifierTest.java`에서 `verify(obj, hash)` 호출을 모두 `verify(obj, hash, null)`로 바꾼다 (기존 테스트는 non-strict 동작 검증 — `null` trust anchor). `AttestationVerifiers.forFormat("none").verify(obj, new byte[32])` 형태를 `.verify(obj, new byte[32], null)`로 일괄 변경. 파일 내 모든 `.verify(` 호출을 확인해 세 번째 인자 `null`을 추가하라.

- [ ] **Step 7: 전체 컴파일 + 기존 테스트 통과 확인**

Run: `cd server && ./gradlew compileJava compileTestJava`
Expected: BUILD SUCCESSFUL.

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AttestationVerifierTest"`
Expected: PASS — 기존 14개 테스트가 `verify(..., null)` 시그니처로 모두 통과.

`RegistrationVerifier`가 `AttestationVerifier.verify()`를 호출하므로 이 단계에서 `RegistrationVerifier`도 컴파일이 깨진다 — Step 8에서 함께 고친다.

- [ ] **Step 8: `RegistrationVerifier` 호출부 임시 갱신**

`RegistrationVerifier.java`에서 `AttestationVerifiers.forFormat(...).verify(attestationObject, clientDataHash)` 호출에 세 번째 인자를 추가한다. Task 8에서 `RegistrationVerificationRequest`에 `MdsTrustAnchorSource` 필드를 정식 추가하기 전까지는 임시로 `null`을 넘긴다:

```java
    AttestationResult attestation =
        AttestationVerifiers.forFormat(attestationObject.format())
            .verify(attestationObject, clientDataHash, null);
```

Run: `cd server && ./gradlew compileJava compileTestJava`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 9: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/ server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AttestationVerifierTest.java
git commit -m "feat(fido2): AttestationVerifier에 MdsTrustAnchorSource 파라미터 추가 + packed full trust anchor 검증

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: AppleAnonymousAttestationVerifier

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AppleAnonymousAttestationVerifier.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AppleAttestationVerifierTest.java`

apple-anonymous attestation(WebAuthn §8.8): attStmt는 `x5c`만 가진다(sig 없음). 검증 핵심 — x5c 첫 cert의 nonce 확장(OID `1.2.840.113635.100.8.2`) 값이 `SHA-256(authData ‖ clientDataHash)`와 일치하고, cert 공개키가 credential 공개키와 일치하는지.

- [ ] **Step 1: 테스트 작성**

`AppleAttestationVerifierTest.java`:

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AppleAnonymousAttestationVerifier;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.model.AttestationObject;
import org.junit.jupiter.api.Test;

class AppleAttestationVerifierTest {

  @Test
  void verifies_valid_apple_attestation() throws Exception {
    AppleAttestationFixture fx = AppleAttestationFixture.valid();
    AttestationObject obj = AttestationObject.parse(fx.attestationObject());
    AttestationResult result =
        new AppleAnonymousAttestationVerifier().verify(obj, fx.clientDataHash(), null);
    assertThat(result.format()).isEqualTo("apple");
  }

  @Test
  void rejects_apple_attestation_with_wrong_nonce() throws Exception {
    AppleAttestationFixture fx = AppleAttestationFixture.withWrongNonce();
    AttestationObject obj = AttestationObject.parse(fx.attestationObject());
    assertThatThrownBy(
            () -> new AppleAnonymousAttestationVerifier().verify(obj, fx.clientDataHash(), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_apple_attestation_missing_x5c() throws Exception {
    AppleAttestationFixture fx = AppleAttestationFixture.missingX5c();
    AttestationObject obj = AttestationObject.parse(fx.attestationObject());
    assertThatThrownBy(
            () -> new AppleAnonymousAttestationVerifier().verify(obj, fx.clientDataHash(), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }
}
```

> **참고:** `AppleAttestationFixture`는 이 Task의 테스트 헬퍼다 — BouncyCastle로 nonce 확장(OID `1.2.840.113635.100.8.2`, 값은 DER로 감싼 `SHA-256(authData‖clientDataHash)`)을 가진 X.509 cert를 만들고, 그 cert 공개키를 credential 공개키로 쓰는 authData를 조립해 apple attestationObject(`{fmt:"apple", attStmt:{x5c:[cert]}, authData}`)를 만든다. `valid()`/`withWrongNonce()`(nonce 확장에 엉뚱한 값)/`missingX5c()`(attStmt 빈 맵) 3개 팩토리. `MdsTestFixtures`의 BouncyCastle cert 빌더 패턴과 `CborTestEncoder`를 재사용해 작성하라. apple cert의 nonce 확장은 `addExtension(new ASN1ObjectIdentifier("1.2.840.113635.100.8.2"), false, <DER SEQUENCE containing [1] EXPLICIT OCTET STRING of the nonce>)` 구조 — Apple 명세 형식을 따른다. 정확한 ASN.1 구조 작성이 까다로우면, verifier 구현 후 fixture를 verifier가 기대하는 형식에 맞춰 작성하라.**

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AppleAttestationVerifierTest"`
Expected: 컴파일 실패.

- [ ] **Step 3: `AppleAnonymousAttestationVerifier` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/attestation/AppleAnonymousAttestationVerifier.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The {@code apple} anonymous attestation format (WebAuthn L3 §8.8). The attestation statement
 * carries only an {@code x5c} certificate chain — no signature field. Verification (per the Apple
 * Anonymous Attestation procedure):
 *
 * <ol>
 *   <li>Concatenate {@code authenticatorData || clientDataHash} and compute its SHA-256 — the
 *       expected nonce.
 *   <li>Read the nonce from the credential certificate's Apple extension (OID
 *       {@code 1.2.840.113635.100.8.2}) and require it to equal the expected nonce.
 *   <li>Require the certificate's public key to equal the credential public key in the
 *       authenticator data.
 * </ol>
 *
 * <p>The certificate chain's trust path (to Apple's root) is validated only in strict mode, when
 * {@code trustAnchors} is non-null.
 */
public final class AppleAnonymousAttestationVerifier implements AttestationVerifier {

  /** Apple's anonymous attestation nonce certificate extension OID. */
  private static final String APPLE_NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";

  @Override
  public String format() {
    return "apple";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object x5cObj = attStmt.get("x5c");
      if (!(x5cObj instanceof List<?> x5cList) || x5cList.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "apple attestation missing x5c");
      }
      Object firstCertObj = x5cList.get(0);
      if (!(firstCertObj instanceof byte[] certDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "apple x5c first element must be a DER-encoded certificate");
      }
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL, "apple attestation has no attested credential");
      }

      // 1. expected nonce = SHA-256(authData || clientDataHash).
      ByteArrayOutputStream nonceInput = new ByteArrayOutputStream();
      nonceInput.writeBytes(attestationObject.authenticatorData().rawBytes());
      nonceInput.writeBytes(clientDataHash);
      byte[] expectedNonce = MessageDigest.getInstance("SHA-256").digest(nonceInput.toByteArray());

      // 2. nonce from the Apple certificate extension must equal the expected nonce.
      byte[] certNonce = appleNonceFromExtension(cert);
      if (!Arrays.equals(certNonce, expectedNonce)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "apple attestation nonce does not match authenticatorData||clientDataHash");
      }

      // 3. the certificate public key must equal the credential public key.
      byte[] certPublicKey = cert.getPublicKey().getEncoded();
      byte[] credentialPublicKey = acd.coseKey().publicKey().getEncoded();
      if (!Arrays.equals(certPublicKey, credentialPublicKey)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "apple attestation cert public key does not match credential public key");
      }

      // strict mode: validate the cert chain to an Apple trust anchor from MDS.
      if (trustAnchors != null) {
        java.util.List<X509Certificate> chain = new java.util.ArrayList<>();
        for (Object o : x5cList) {
          if (o instanceof byte[] der) {
            chain.add(
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
          }
        }
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(acd.aaguid());
        java.util.UUID aaguid = new java.util.UUID(buf.getLong(), buf.getLong());
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "apple attestation chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("apple", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (RuntimeException | java.security.GeneralSecurityException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "apple attestation verification failed: "
              + e.getMessage());
    }
  }

  /**
   * Extract the nonce octets from the Apple anonymous attestation certificate extension. The
   * extension value is a DER {@code SEQUENCE} whose single element is a context-tagged
   * {@code [1] EXPLICIT} wrapping an {@code OCTET STRING} of the SHA-256 nonce.
   */
  private static byte[] appleNonceFromExtension(X509Certificate cert)
      throws Fido2VerificationException {
    byte[] raw = cert.getExtensionValue(APPLE_NONCE_EXTENSION_OID);
    if (raw == null) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "apple attestation cert has no nonce extension");
    }
    // getExtensionValue wraps the extension content in an outer OCTET STRING.
    byte[] inner = DerUtil.unwrapOctetString(raw, "apple nonce extension outer OCTET STRING");
    // inner = SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } } — walk to the innermost OCTET STRING.
    return DerUtil.extractAppleNonce(inner);
  }
}
```

> **참고:** `DerUtil`은 이 Task에서 함께 만드는 작은 DER 파싱 유틸이다 (`fido2.attestation` 패키지). `PackedAttestationVerifier`의 `unwrapDerOctetString`과 중복되므로 — 이 Task에서 `DerUtil`로 추출·통합하고 `PackedAttestationVerifier`도 `DerUtil`을 쓰도록 리팩터링하라. `DerUtil`은 `unwrapOctetString(byte[], String)`(단일 OCTET STRING 언랩, 기존 `unwrapDerOctetString` 로직)과 `extractAppleNonce(byte[])`(SEQUENCE → `[1] EXPLICIT` → OCTET STRING 경로를 걸어 nonce 바이트 반환)를 제공한다. ASN.1 파싱이 까다로우면 — `fido2` 코어가 이미 nimbus를 의존하므로(Task 2), nimbus가 끌어오는 `com.nimbusds` 의존 대신, 이 케이스는 BouncyCastle `ASN1` 파서를 쓰는 게 가장 안전하다. 단 BouncyCastle은 현재 `testImplementation`이므로 — production에서 BouncyCastle ASN.1을 쓰려면 `bcprov-jdk18on`을 `implementation`으로 올려야 한다. **이 결정(수동 DER 파싱 vs BouncyCastle production 승격)은 구현 시 판단하되, 선택과 이유를 보고하라.** 수동 파싱이 가능하면 의존성 추가 없이 수동 파싱을 우선한다.**

- [ ] **Step 4: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AppleAttestationVerifierTest"`
Expected: PASS (3 tests).

- [ ] **Step 5: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/attestation/ server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/
git commit -m "feat(fido2): AppleAnonymousAttestationVerifier — apple attestation 검증 추가

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: AndroidKeyAttestationVerifier + 레지스트리 등록

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AndroidKeyAttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AndroidKeyAttestationVerifierTest.java`

android-key attestation(WebAuthn §8.4): attStmt는 `alg`, `sig`, `x5c`. 검증 — x5c 첫 cert 공개키로 `authData‖clientDataHash` 서명 검증, cert 공개키 = credential 공개키 일치, Android Key Attestation 확장(OID `1.3.6.1.4.1.11129.2.1.17`)의 attestationChallenge가 clientDataHash와 일치.

- [ ] **Step 1: 테스트 작성**

`AndroidKeyAttestationVerifierTest.java`:

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AndroidKeyAttestationVerifier;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.model.AttestationObject;
import org.junit.jupiter.api.Test;

class AndroidKeyAttestationVerifierTest {

  @Test
  void verifies_valid_android_key_attestation() throws Exception {
    AndroidKeyFixture fx = AndroidKeyFixture.valid();
    AttestationObject obj = AttestationObject.parse(fx.attestationObject());
    AttestationResult result =
        new AndroidKeyAttestationVerifier().verify(obj, fx.clientDataHash(), null);
    assertThat(result.format()).isEqualTo("android-key");
  }

  @Test
  void rejects_android_key_with_invalid_signature() throws Exception {
    AndroidKeyFixture fx = AndroidKeyFixture.invalidSignature();
    AttestationObject obj = AttestationObject.parse(fx.attestationObject());
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, fx.clientDataHash(), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_android_key_with_wrong_attestation_challenge() throws Exception {
    AndroidKeyFixture fx = AndroidKeyFixture.wrongChallenge();
    AttestationObject obj = AttestationObject.parse(fx.attestationObject());
    assertThatThrownBy(
            () -> new AndroidKeyAttestationVerifier().verify(obj, fx.clientDataHash(), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }
}
```

> **참고:** `AndroidKeyFixture`는 이 Task의 테스트 헬퍼다 — BouncyCastle로 Android Key Attestation 확장(OID `1.3.6.1.4.1.11129.2.1.17`, 값은 `KeyDescription` ASN.1 SEQUENCE — 그 안 `attestationChallenge` OCTET STRING이 clientDataHash)을 가진 cert를 만들고, cert 키로 `authData‖clientDataHash`를 서명한다. `valid()`/`invalidSignature()`/`wrongChallenge()`(확장의 challenge가 엉뚱한 값) 3개 팩토리. KeyDescription 전체 ASN.1 구조는 복잡하므로 — verifier가 실제로 읽는 필드(attestationChallenge)만 정확히 만들고 나머지 SEQUENCE 필드는 최소 더미로 채워도 된다. verifier 구현 후 fixture를 verifier 기대 형식에 맞춰 작성하라.**

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AndroidKeyAttestationVerifierTest"`
Expected: 컴파일 실패.

- [ ] **Step 3: `AndroidKeyAttestationVerifier` 구현**

`server/src/main/java/com/crosscert/passkey/fido2/attestation/AndroidKeyAttestationVerifier.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The {@code android-key} attestation format (WebAuthn L3 §8.4). The attestation statement carries
 * {@code alg}, {@code sig}, and an {@code x5c} chain. Verification:
 *
 * <ol>
 *   <li>Verify {@code sig} over {@code authenticatorData || clientDataHash} with the public key of
 *       the credential certificate (x5c[0]).
 *   <li>Require that certificate's public key to equal the credential public key.
 *   <li>Require the Android Key Attestation extension (OID {@code 1.3.6.1.4.1.11129.2.1.17})'s
 *       {@code attestationChallenge} to equal {@code clientDataHash}.
 * </ol>
 *
 * <p>The certificate chain trust path is validated only in strict mode ({@code trustAnchors}
 * non-null).
 */
public final class AndroidKeyAttestationVerifier implements AttestationVerifier {

  /** The Android Key Attestation certificate extension OID. */
  private static final String ANDROID_KEY_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";

  @Override
  public String format() {
    return "android-key";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object sigObj = attStmt.get("sig");
      Object algObj = attStmt.get("alg");
      Object x5cObj = attStmt.get("x5c");
      if (!(sigObj instanceof byte[] signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation missing sig");
      }
      if (!(algObj instanceof Long algValue)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation missing alg");
      }
      if (!(x5cObj instanceof List<?> x5cList) || x5cList.isEmpty()
          || !(x5cList.get(0) instanceof byte[] certDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation missing x5c");
      }
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL,
            "android-key attestation has no attested credential");
      }

      // 1. verify sig over authData || clientDataHash with the credential cert public key.
      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.writeBytes(attestationObject.authenticatorData().rawBytes());
      signedData.writeBytes(clientDataHash);
      Signature verifier = Signature.getInstance(jcaAlgorithmForCoseAlg(algValue));
      verifier.initVerify(cert.getPublicKey());
      verifier.update(signedData.toByteArray());
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-key attestation signature invalid");
      }

      // 2. the certificate public key must equal the credential public key.
      if (!Arrays.equals(
          cert.getPublicKey().getEncoded(), acd.coseKey().publicKey().getEncoded())) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-key cert public key does not match credential public key");
      }

      // 3. the Android Key Attestation extension's attestationChallenge must equal clientDataHash.
      byte[] attestationChallenge = androidKeyAttestationChallenge(cert);
      if (!Arrays.equals(attestationChallenge, clientDataHash)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-key attestationChallenge does not match clientDataHash");
      }

      if (trustAnchors != null) {
        List<X509Certificate> chain = new java.util.ArrayList<>();
        for (Object o : x5cList) {
          if (o instanceof byte[] der) {
            chain.add(
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
          }
        }
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(acd.aaguid());
        java.util.UUID aaguid = new java.util.UUID(buf.getLong(), buf.getLong());
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "android-key chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("android-key", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (RuntimeException | java.security.GeneralSecurityException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "android-key attestation verification failed: " + e.getMessage());
    }
  }

  /**
   * Extract the {@code attestationChallenge} OCTET STRING from the Android Key Attestation
   * certificate extension (OID {@code 1.3.6.1.4.1.11129.2.1.17}). The extension content is a
   * {@code KeyDescription} SEQUENCE whose 5th element (index 4) is the {@code attestationChallenge}
   * OCTET STRING.
   */
  private static byte[] androidKeyAttestationChallenge(X509Certificate cert)
      throws Fido2VerificationException {
    byte[] raw = cert.getExtensionValue(ANDROID_KEY_EXTENSION_OID);
    if (raw == null) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "android-key cert has no Key Attestation extension");
    }
    byte[] keyDescription =
        DerUtil.unwrapOctetString(raw, "android-key extension outer OCTET STRING");
    return DerUtil.androidKeyAttestationChallenge(keyDescription);
  }

  private static String jcaAlgorithmForCoseAlg(long coseAlg) throws Fido2VerificationException {
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default ->
          throw new Fido2VerificationException(
              FailureReason.ATTESTATION_INVALID,
              "android-key attestation unsupported alg: " + coseAlg);
    };
  }
}
```

> **참고:** `DerUtil.androidKeyAttestationChallenge(byte[])`는 Task 6의 `DerUtil`에 추가하는 메서드 — `KeyDescription` SEQUENCE를 파싱해 index 4의 OCTET STRING(attestationChallenge)을 반환한다. SEQUENCE 요소 순회 파싱이 필요하다. Task 6에서 BouncyCastle ASN.1을 production으로 올리기로 했다면 `ASN1Sequence`로 간단히 파싱 가능; 수동 파싱이면 SEQUENCE 요소를 순회하는 로직을 `DerUtil`에 구현하라.

- [ ] **Step 4: `AttestationVerifiers` 레지스트리에 등록**

`AttestationVerifiers.java`의 `REGISTRY` 맵을 다음으로 교체:

```java
  private static final Map<String, AttestationVerifier> REGISTRY =
      Map.of(
          "none", new NoneAttestationVerifier(),
          "packed", new PackedAttestationVerifier(),
          "apple", new AppleAnonymousAttestationVerifier(),
          "android-key", new AndroidKeyAttestationVerifier());
```

javadoc도 "none, packed, apple, android-key를 등록" 으로 갱신.

- [ ] **Step 5: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.*"`
Expected: PASS — android-key 3개 + apple 3개 + 기존 packed/none 14개.

- [ ] **Step 6: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/attestation/ server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/
git commit -m "feat(fido2): AndroidKeyAttestationVerifier + apple/android-key 레지스트리 등록

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: MdsBlobProvider 재배선 — webauthn4j delegate 제거

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobProvider.java`
- Delete: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsTrustAnchorRepositoryConfig.java`
- Create: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsConfig.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsBlobProviderTest.java`

`MdsBlobProvider`의 webauthn4j `FidoMDS3MetadataBLOBProvider` delegate를 — Spring `RestClient` fetch + `fido2.mds.MetadataBlob.parse()`로 교체한다. webauthn4j 전용 `MdsTrustAnchorRepositoryConfig`는 제거하고, 자체 `MdsTrustAnchorSource` 빈을 노출하는 `MdsConfig`를 만든다.

> **참고:** 이 Task는 `credential.metadata` 인프라 계층 수정이다 — Spring 빈·`@Scheduled`를 다룬다. `MdsBlobProvider`/`MdsRefreshScheduler`는 `fido2` 코어가 아니므로 Spring 의존 허용. **strict 경로(`RegistrationService.verifyWithWebauthn4j()`)는 이 Task에서 건드리지 않는다** — Phase 3는 strict 경로를 전환하지 않는다. webauthn4j strict `WebAuthnManager`(`WebAuthnConfig`)도 그대로 둔다. 단 `MdsTrustAnchorRepositoryConfig`가 만들던 webauthn4j `TrustAnchorRepository` 빈을 제거하므로 — strict `WebAuthnManager`가 그 빈에 의존하면 컴파일·기동이 깨진다. `WebAuthnConfig`의 strict 매니저 빈이 `TrustAnchorRepository`를 주입받는다면, **Phase 3에서는 `MdsTrustAnchorRepositoryConfig`를 제거하지 말고 유지**하라 — webauthn4j strict 경로가 Phase 4까지 살아있어야 하므로. 즉 이 Task는 `MdsBlobProvider`가 자체 `MetadataBlob`도 파싱하도록 **병행 추가**하고, webauthn4j delegate는 strict 경로용으로 Phase 4까지 남긴다. 아래 Step을 이 원칙으로 수행하라.

- [ ] **Step 1: `WebAuthnConfig`·`MdsBlobProvider`의 webauthn4j 결합 확인**

Run: `cd server && grep -rn "TrustAnchorRepository\|FidoMDS3MetadataBLOBProvider\|MetadataBLOBProvider" server/src/main/java/com/crosscert/passkey/credential/webauthn/ server/src/main/java/com/crosscert/passkey/credential/metadata/`

`WebAuthnConfig`의 strict `WebAuthnManager`가 `TrustAnchorRepository`를 주입받는지 확인한다. 주입받으면 — `MdsTrustAnchorRepositoryConfig`와 `MdsBlobProvider`의 webauthn4j delegate는 Phase 3에서 **유지**한다 (Phase 4에서 strict 전환과 함께 제거).

- [ ] **Step 2: `MdsBlobProvider`에 자체 `MetadataBlob` 파싱 병행 추가**

`MdsBlobProvider`에 — 기존 webauthn4j delegate는 그대로 두고, 자체 `MetadataBlob`도 함께 적재하는 필드·로직을 추가한다. `refresh()`가 BLOB JWS를 `RestClient`로 가져와 `MetadataBlob.parse()`로도 파싱하고, `MdsTrustAnchorSource`를 `AtomicReference`에 스왑한다. 새 접근자 `currentTrustAnchorSource()`를 추가한다.

`MdsBlobProvider.java`에 추가할 필드·메서드 (기존 webauthn4j 필드·메서드는 유지):

```java
  // --- Phase 3: in-house MDS parsing (parallel to the webauthn4j delegate kept for the strict
  // WebAuthnManager until Phase 4 retires it). ---
  private final AtomicReference<com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource>
      trustAnchorSource = new AtomicReference<>();

  /** The current in-house trust anchor source, or null before the first successful refresh. */
  public com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource currentTrustAnchorSource() {
    return trustAnchorSource.get();
  }

  /**
   * Fetch the BLOB JWS and parse it with the in-house {@code fido2.mds} parser, swapping in a fresh
   * {@link com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource}. Called from {@link #refresh()}
   * alongside the webauthn4j delegate refresh.
   */
  private void refreshInHouse() {
    try {
      String jws =
          restClient.get().uri(props.getBlobUrl()).retrieve().body(String.class);
      com.crosscert.passkey.fido2.mds.MetadataBlob blob =
          com.crosscert.passkey.fido2.mds.MetadataBlob.parse(jws, rootCa);
      trustAnchorSource.set(
          new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(blob.entries()));
      log.info("mds.inhouse.refresh.success entries={}", blob.entries().size());
    } catch (Exception e) {
      // fail-soft: keep the stale in-house source, same policy as the webauthn4j delegate.
      log.error("mds.inhouse.refresh.failed reason={}", e.getMessage(), e);
    }
  }
```

`restClient`·`rootCa` 필드를 생성자에서 초기화하도록 추가한다 (`rootCa`는 이미 `loadRootCa`로 로드하므로 필드로 보관, `restClient`는 `RestClient.create()`). 생성자와 `refresh()`에 `refreshInHouse()` 호출을 추가한다 — `refresh()`의 webauthn4j `delegate.refresh()` 뒤에 `refreshInHouse()`를 호출.

> **참고:** 정확한 필드 추가·생성자 수정은 현재 `MdsBlobProvider.java` 전문을 읽고 기존 구조(`delegate`, `loadRootCa`, `warmUp`, `lastBlob`)에 맞춰 통합하라. 핵심은 — webauthn4j delegate 경로는 보존(strict 경로가 Phase 4까지 사용), 자체 `MetadataBlob` 파싱을 병행 추가, `currentTrustAnchorSource()`로 노출.

- [ ] **Step 3: `MdsConfig` 생성 — MdsTrustAnchorSource 빈 노출**

`server/src/main/java/com/crosscert/passkey/credential/metadata/MdsConfig.java`:

```java
package com.crosscert.passkey.credential.metadata;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the in-house {@link MdsTrustAnchorSource} for the self-implemented strict attestation
 * path. The bean is a thin accessor over {@link MdsBlobProvider}, which holds the live source and
 * swaps it on each refresh — so callers always see the latest BLOB without rebuilding the bean.
 *
 * <p>Phase 3: this bean coexists with the webauthn4j {@code TrustAnchorRepository} (wired by
 * {@code MdsTrustAnchorRepositoryConfig}); Phase 4 removes the webauthn4j wiring once the strict
 * registration path no longer uses webauthn4j.
 */
@Configuration
@ConditionalOnBean(MdsBlobProvider.class)
public class MdsConfig {

  /**
   * A supplier-style bean returning the current trust anchor source. {@code RegistrationService}
   * (Phase 4) calls this to obtain strict-mode trust anchors; until then it is available for
   * integration tests.
   */
  @Bean
  public MdsTrustAnchorSourceHolder mdsTrustAnchorSourceHolder(MdsBlobProvider provider) {
    return provider::currentTrustAnchorSource;
  }

  /** Functional holder so callers depend on an interface, not on {@code MdsBlobProvider}. */
  @FunctionalInterface
  public interface MdsTrustAnchorSourceHolder {
    /** The current trust anchor source, or null before the first successful BLOB refresh. */
    MdsTrustAnchorSource current();
  }
}
```

- [ ] **Step 4: `MdsBlobProviderTest` 작성**

`server/src/test/java/com/crosscert/passkey/unit/credential/metadata/MdsBlobProviderTest.java` — `refreshInHouse()`가 BLOB을 파싱해 `MdsTrustAnchorSource`를 노출하는지 검증. RestClient는 mock 또는 `MockRestServiceServer`로 BLOB JWS를 반환하게 한다. fixture는 `MdsTestFixtures`(Task 2) 재사용.

```java
package com.crosscert.passkey.unit.credential.metadata;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.unit.fido2.mds.MdsTestFixtures;
import org.junit.jupiter.api.Test;

/**
 * Verifies MdsBlobProvider's in-house parsing path. Full Spring wiring (RestClient, root CA
 * resource) is covered by the Phase 3 integration test; this unit test pins the BLOB-to-source
 * transformation.
 */
class MdsBlobProviderTest {

  @Test
  void parses_blob_into_trust_anchor_source() throws Exception {
    MdsTestFixtures.Pki pki = MdsTestFixtures.buildPki();
    String payload =
        "{\"no\":1,\"nextUpdate\":\"2099-01-01\",\"entries\":["
            + "{\"aaguid\":\"00000000-0000-0000-0000-00000000000a\","
            + "\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\"}],"
            + "\"metadataStatement\":{\"attestationRootCertificates\":[]}}]}";
    String jws = MdsTestFixtures.signBlob(payload, pki);

    com.crosscert.passkey.fido2.mds.MetadataBlob blob =
        com.crosscert.passkey.fido2.mds.MetadataBlob.parse(jws, pki.rootCa());
    com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource source =
        new com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource(blob.entries());

    assertThat(
            source.findEntry(
                java.util.UUID.fromString("00000000-0000-0000-0000-00000000000a")))
        .isPresent();
  }
}
```

> **참고:** `MdsBlobProvider`의 `refreshInHouse()`를 직접 단위 테스트하려면 RestClient 모킹이 필요해 복잡하다 — 위 테스트는 BLOB→source 변환의 핵심(`MetadataBlob.parse` + `MdsTrustAnchorSource`)을 검증한다. `MdsBlobProvider`의 Spring 통합(RestClient fetch + 빈 wiring)은 Task 9의 Phase 3 통합 테스트에서 커버한다.

- [ ] **Step 5: 컴파일 + 테스트 통과 확인**

Run: `cd server && ./gradlew compileJava compileTestJava`
Expected: BUILD SUCCESSFUL.

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.metadata.MdsBlobProviderTest"`
Expected: PASS.

- [ ] **Step 6: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/credential/metadata/ server/src/test/java/com/crosscert/passkey/unit/credential/metadata/
git commit -m "feat(fido2): MdsBlobProvider에 자체 MDS 파싱 병행 추가 + MdsConfig

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Phase 3 마무리 — ArchUnit 갱신 + 전체 검증

**Files:**
- Modify: `server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java`
- Modify: `docs/architecture.md`

- [ ] **Step 1: ArchUnit Rule 7 주석 갱신 — nimbus 허용 명시**

`PackageArchitectureTest.java`의 Rule 7(`fido2_core_is_pure`) 주석에 nimbus-jose-jwt 허용을 명시한다. Rule 7의 주석 블록을 다음으로 교체:

```java
  // Rule 7: the fido2 core is a pure WebAuthn implementation — it must not depend on any domain
  // package, on Spring, or on the application's exception types. Only java.*/javax.* (JCA, LDAP
  // name parsing) + the fido2 package itself + Jackson (clientDataJSON parsing) + nimbus-jose-jwt
  // (MDS3 BLOB JWS verification) are permitted. The domain packages are fully qualified under ROOT
  // so the pattern does not accidentally match JDK packages such as javax.security.auth.
```

Rule 7의 `dependOnClassesThat().resideInAnyPackage(...)` deny-list는 변경하지 않는다 — `com.nimbusds`는 deny-list(도메인 패키지 + `org.springframework`)에 없으므로 이미 허용된다. 주석만 갱신.

- [ ] **Step 2: ArchUnit 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.architecture.PackageArchitectureTest"`
Expected: PASS (7 rules). `fido2.mds`가 nimbus를 import해도 Rule 7 통과.

- [ ] **Step 3: 전체 검증 — `./gradlew check`**

Run: `cd server && ./gradlew check`
Expected: BUILD SUCCESSFUL — unit + integration + ArchUnit + spotless 전체.

> **회귀 감지:** 이 단계가 Phase 3가 무관한 통합 테스트(테넌트 격리·admin)를 깨지 않았는지 확인하는 게이트다. integration 테스트가 깨지면 — `MdsBlobProvider` 변경이나 새 빈(`MdsConfig`)이 Spring context를 깬 것이므로 추적해 수정한다. (Oracle DB 필요 — 통합 테스트 전 `docker compose up -d` + 필요 시 schema reset.)

- [ ] **Step 4: `architecture.md` §11 변경 이력 추가**

`docs/architecture.md`의 §11 변경 이력 테이블 마지막에 항목 추가:

```
| 2026-05-23 | FIDO2 코어 Milestone B Phase 3 | webauthn4j 제거 1단계 — `fido2.mds` 패키지 신설(MDS3 BLOB JWS 자체 파싱: 서명검증 nimbus-jose-jwt, x5c 체인 JCA `CertPathValidator`, payload 해석 자체 구현), `MetadataBlob`/`MetadataEntry`/`StatusReport`/`MdsTrustAnchorSource`. `AttestationVerifier.verify()`에 nullable `MdsTrustAnchorSource` 파라미터 추가 — non-null이면 strict(cert chain trust anchor 검증 + revoked 거부), null이면 non-strict. `AttestationCertPathValidator`(JCA PKIX 래퍼). attestation verifier 추가: `apple`(nonce 확장 검증), `android-key`(attestationChallenge 검증), `packed` full에 trust anchor 검증 추가. `MdsBlobProvider`가 자체 `MetadataBlob` 파싱을 병행(webauthn4j delegate는 strict 경로용으로 Phase 4까지 유지). `Fido2VerificationException.FailureReason`에 `TRUST_PATH_INVALID`/`MDS_TRUST_FAILED`/`AUTHENTICATOR_REVOKED` 추가. strict 등록 경로(`RegistrationService.verifyWithWebauthn4j`)는 Phase 3에서 미전환 — Phase 4 대상. 설계: `docs/superpowers/specs/2026-05-23-fido2-core-milestone-b-design.md`. |
```

- [ ] **Step 5: 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java docs/architecture.md
git commit -m "docs(fido2): Milestone B Phase 3 — ArchUnit Rule 7 nimbus 허용 주석 + architecture.md 갱신

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase 3 완료 기준

- [ ] `fido2.mds` 패키지 — `MetadataBlob`(BLOB JWS 자체 파싱)·`MetadataEntry`·`StatusReport`·`MdsTrustAnchorSource`
- [ ] `AttestationCertPathValidator` — JCA PKIX 체인 검증
- [ ] `AttestationVerifier.verify()`에 nullable `MdsTrustAnchorSource` 파라미터 — strict/non-strict 구분
- [ ] `packed` full 경로에 trust anchor 검증, `apple`·`android-key` verifier 추가
- [ ] `MdsBlobProvider`가 자체 `MetadataBlob` 파싱 병행 (webauthn4j delegate는 strict용으로 잔존)
- [ ] strict 등록 경로(`RegistrationService.verifyWithWebauthn4j`)는 미전환 — Phase 4 대상
- [ ] `webauthn4j-core`·`webauthn4j-metadata` 의존성 잔존 — Phase 4에서 제거
- [ ] ArchUnit Rule 7 통과 (nimbus 허용)
- [ ] `./gradlew check` 전체 통과

## Phase 4 예고 (별도 계획)

- attestation verifier: `android-safetynet`(JWS 기반)·`fido-u2f`·`tpm`
- `RegistrationService`의 strict 경로를 `verifyWithCore`로 단일화 — `verifyWithWebauthn4j` 제거, `MdsTrustAnchorSource` 주입
- `RegistrationVerificationRequest`에 `MdsTrustAnchorSource` 필드 정식 추가
- `WebAuthnConfig`·`MdsTrustAnchorRepositoryConfig` 제거, `MdsBlobProvider`의 webauthn4j delegate 제거
- `webauthn4j-core`·`webauthn4j-metadata` 의존성 삭제
- 차등 테스트를 골든 벡터 기반으로 전환
- strict 경로 통합 테스트 신규 추가
