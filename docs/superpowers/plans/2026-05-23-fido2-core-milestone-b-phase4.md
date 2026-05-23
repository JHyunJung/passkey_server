# FIDO2 코어 Milestone B — Phase 4 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 자체 코어에 남은 attestation 포맷 3종(`android-safetynet` / `fido-u2f` / `tpm`)을 추가하고, strict 등록 경로를 자체 코어로 단일화한 뒤, `webauthn4j-core`·`webauthn4j-metadata` 의존성을 production에서 완전히 제거한다.

**Architecture:** verifier 3종을 먼저 추가해 자체 코어가 6포맷(none/packed/apple/android-key/android-safetynet/fido-u2f/tpm)을 처리할 수 있게 만든 뒤, `RegistrationVerificationRequest`에 nullable `MdsTrustAnchorSource`를 추가해 `RegistrationVerifier`가 `AttestationVerifier.verify()`의 3-번째 파라미터로 전달한다. `RegistrationService`는 `policy.isMdsStrict()`에 따라 `MdsTrustAnchorSourceHolder` 빈을 주입하거나 null을 넘기는 1-라인 분기로 축소되고, `verifyWithWebauthn4j()`는 삭제된다. webauthn4j 잔존 코드 4파일과 의존성 2종을 단계적으로 제거하고, 차등 테스트는 W3C 명세 예제 + BouncyCastle 자체 생성 + FIDO conformance 골든 벡터 기반으로 전환한다.

**Tech Stack:** Java 17, Spring Boot 3.5, nimbus-jose-jwt 9.40(JWS), JCA(`java.security.cert`, `Signature`), JUnit 5, AssertJ, BouncyCastle(`bcpkix-jdk18on` — testImplementation, cert·MDS BLOB fixture), ArchUnit 1.3, Google Java Format(Spotless), Oracle Free 23(integration).

**선행 상태:** Milestone B Phase 3 완료(MDS 인프라·packed-full strict·apple·android-key 자체 코어). `AttestationVerifier.verify(obj, hash, trustAnchors)`는 이미 3-파라미터 시그니처. `MdsConfig.MdsTrustAnchorSourceHolder` 빈 존재. strict 경로는 여전히 `RegistrationService.verifyWithWebauthn4j()`가 webauthn4j 사용. `webauthn4j-core`·`webauthn4j-metadata` production 의존성 잔존.

**설계 근거:** `docs/superpowers/specs/2026-05-23-fido2-core-milestone-b-design.md` 전체, 특히 §11(Phase 4 상세 결정).

---

## 파일 구조

신규 생성 — verifier (`server/src/main/java/com/crosscert/passkey/fido2/attestation/`):

| 파일 | 책임 |
|---|---|
| `AndroidSafetyNetAttestationVerifier.java` | `fmt="android-safetynet"`. response는 JWS — nimbus로 파싱·서명검증. payload `nonce == SHA-256(authData || clientDataHash)`. `ctsProfileMatch=true`. attestation cert(x5c[0])가 `attest.android.com` SAN을 갖는지. strict 시 chain → MDS trust anchor. |
| `FidoU2fAttestationVerifier.java` | `fmt="fido-u2f"`. 레거시 U2F. x5c[0]의 ECDSA P-256 키로 `sig` 검증 — signedData = `0x00 || rpIdHash(32) || clientDataHash(32) || credentialId || publicKeyU2F(65)`. AAGUID는 zero(레거시). strict 시 chain → MDS trust anchor. |
| `TpmAttestationVerifier.java` | `fmt="tpm"`. 위 11.2 6단계 검증. TPM 1.2 거부. |

신규 생성 — TPM 이진 파서 (`server/src/main/java/com/crosscert/passkey/fido2/tpm/`):

| 파일 | 책임 |
|---|---|
| `TpmsAttest.java` | TPM2_ST_ATTEST_CERTIFY 구조의 이진 파서 — magic / type / qualifiedSigner / extraData / clockInfo / firmwareVersion / attested(TPMS_CERTIFY_INFO: name·qualifiedName). |
| `TpmtPublic.java` | TPMT_PUBLIC 구조 — type / nameAlg / objectAttributes / authPolicy / parameters / unique. RSA(2048)·ECC(P-256) 지원. credential public key 일치 비교용. |
| `TpmException.java` | TPM 파싱/검증 실패 (unchecked, 내부용). |

신규 생성 — 통합 테스트 + MDS fixture:

| 파일 | 책임 |
|---|---|
| `server/src/test/java/com/crosscert/passkey/integration/credential/RegistrationStrictIntegrationTest.java` | Oracle DB + `passkey.mds.enabled=true` + 고정 MDS BLOB. 6 fmt × (happy-path + reject) + `none` happy = 13 test methods. |
| `server/src/test/resources/fido2/mds-blob-fixture.jws` | BouncyCastle로 자체 생성한 MDS3 BLOB JWS(테스트 root CA 서명). 6포맷용 AAGUID entries + revoked entry 1건 포함. |
| `server/src/test/resources/fido2/mds-blob-fixture-root.cer` | 위 JWS의 root CA — `MetadataBlob.parse(jws, rootCa)`에 넘김. |
| `server/src/test/java/com/crosscert/passkey/unit/fido2/AttestationTestCerts.java` | 공용 헬퍼: `selfSignedCa`, `leafSignedBy`, `aaguidOfAttestation` — Apple/Android Key/Packed/신규 3종 verifier 테스트의 중복 제거. |
| `server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationGoldenVectorTest.java` | 차등 테스트 대체. 골든 벡터 입력 → 자체 코어 결과 검증. |
| `server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionGoldenVectorTest.java` | 같은 패턴, 인증용. |
| `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/DerUtilTest.java` | 현재 verifier 테스트가 간접 커버하는 `DerUtil`을 직접 커버. |

수정 — fido2 코어:

| 파일 | 변경 |
|---|---|
| `attestation/AttestationVerifier.java` | sealed `permits`에 신규 verifier 3종 추가. |
| `attestation/AttestationVerifiers.java` | 레지스트리에 `android-safetynet`·`fido-u2f`·`tpm` 등록. |
| `RegistrationVerificationRequest.java` | nullable `MdsTrustAnchorSource trustAnchors` 필드 추가. |
| `RegistrationVerifier.java` | `req.trustAnchors()`를 `AttestationVerifier.verify()` 3-번째 인자로 전달 (현재 `null` 하드코드). |
| `Fido2VerificationException.java` | `FailureReason`에 `INVALID_ATTESTATION_FORMAT`·`INVALID_TPM_STRUCTURE` 추가. |

수정 — credential 도메인 (webauthn4j 제거 단계):

| 파일 | 변경 |
|---|---|
| `credential/service/RegistrationService.java` | `verifyWithWebauthn4j()` + `AttestationFacts` private record 삭제. `verifyWithCore()`가 `MdsTrustAnchorSource`를 받도록 시그니처 확장. `policy.isMdsStrict()` 분기는 `trustAnchorSource` 결정으로 단순화. `MdsTrustAnchorSourceHolder` + (mdsStrict 시) null-체크 → `MDS_UNAVAILABLE`. webauthn4j import 모두 제거. |
| `credential/webauthn/WebAuthnConfig.java` | 삭제. |
| `credential/metadata/MdsTrustAnchorRepositoryConfig.java` | 삭제. |
| `credential/metadata/MdsBlobProvider.java` | webauthn4j `FidoMDS3MetadataBLOBProvider` delegate / `MetadataBLOBProvider` 인터페이스 / `lastBlob` / `provide()` 삭제. 자체 `MetadataBlob`만 노출. `lastBlob`을 참조하던 `MdsDiagController`도 자체 모델로 전환. |
| `credential/metadata/MdsDiagController.java` | `com.webauthn4j.metadata.data.MetadataBLOB` import → 자체 모델로 교체. `entryCount`/`nextUpdate`/`serialNumber` 추출 경로 변경. |

수정 — 의존성·아키텍처 가드:

| 파일 | 변경 |
|---|---|
| `server/build.gradle.kts` | `webauthn4j-core`·`webauthn4j-metadata` `implementation(...)` 2줄 + 주석 블록 삭제. |
| `server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java` | Rule 7 주석에서 "Phase 3" 표기 → "Phase 4 완료 — production에서 webauthn4j 완전 제거" 갱신. 신규 production-only Rule 추가: `..` 패키지에서 `com.webauthn4j..` import 금지. |

삭제 — 차등 테스트(webauthn4j 비교 불가):

| 파일 | 처리 |
|---|---|
| `server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionDifferentialTest.java` | 삭제 (Task 9에서 `AssertionGoldenVectorTest`로 교체된 뒤). |
| `server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationDifferentialTest.java` | 삭제. |
| `server/src/test/java/com/crosscert/passkey/unit/fido2/Fido2Fixtures.java` | webauthn4j import 삭제·BouncyCastle-only로 재작성 → 골든 벡터 테스트와 신규 verifier 테스트의 공통 빌더. |

수정 — 문서:

| 파일 | 변경 |
|---|---|
| `docs/architecture.md` §11 | 변경 이력에 "Phase 4 — webauthn4j 완전 제거, 자체 코어 단일화" 추가. §1 Tech Stack에서 webauthn4j 제거. |

---

## Task 순서 개요

| # | Task | 핵심 산출물 |
|---|------|-------------|
| 1 | `AndroidSafetyNetAttestationVerifier` + 단위 테스트 | nimbus JWS 검증, nonce·ctsProfileMatch·SAN |
| 2 | `FidoU2fAttestationVerifier` + 단위 테스트 | 레거시 U2F signedData 포맷, ECDSA P-256 |
| 3 | `fido2.tpm` 이진 파서 (TpmsAttest·TpmtPublic·TpmException) + 단위 테스트 | TPM 2.0 구조 파싱 |
| 4 | `TpmAttestationVerifier` (TPM 2.0 only) + 단위 테스트 | 6단계 검증, TPM 1.2 거부 |
| 5 | `AttestationTestCerts` 공용 헬퍼 추출 + `DerUtilTest` 추가 + FQN import 정리 | 테스트 중복 제거 |
| 6 | `RegistrationVerificationRequest`·`RegistrationVerifier` strict 와이어링 | nullable `MdsTrustAnchorSource` 전달 |
| 7 | `RegistrationService.verifyWithCore`를 strict까지 단일화 | `verifyWithWebauthn4j` + `AttestationFacts` 삭제 |
| 8 | `RegistrationStrictIntegrationTest` + MDS BLOB fixture | 6 fmt × happy+reject + none happy = 13 tests |
| 9 | 골든 벡터 기반 테스트 전환 + `Fido2Fixtures` 재작성 | `*GoldenVectorTest` 신규, `*DifferentialTest` 삭제 |
| 10 | webauthn4j import 단계적 제거 (RegistrationService → Config 2종 → MdsBlobProvider → MdsDiagController) | production에서 `com.webauthn4j` import 0건 |
| 11 | `build.gradle.kts`에서 webauthn4j 의존성 2종 삭제 + ArchUnit 가드 추가 | `./gradlew check` 통과 + transitive 없음 확인 |
| 12 | `FailureReason.UNSUPPORTED_ALGORITHM` 정리 + `docs/architecture.md` §11 갱신 + 최종 정리 | Phase 4 클로즈 |

각 Task는 단일 commit. 각 Task 끝에서 `./gradlew check` 통과. Task 10·11 사이에 회귀 가능성이 가장 높으므로 substep별 check를 강제.

---

## Task 1: `AndroidSafetyNetAttestationVerifier`

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AndroidSafetyNetAttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java:17-21` (sealed `permits`에 추가)
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java:14-19` (레지스트리 등록)
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AndroidSafetyNetAttestationVerifierTest.java`

- [ ] **Step 1: 실패 테스트 작성 — happy path (non-strict)**

`AndroidSafetyNetAttestationVerifierTest.java`:

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AndroidSafetyNetAttestationVerifier;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.model.AttestationObject;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

class AndroidSafetyNetAttestationVerifierTest {

  private final AndroidSafetyNetAttestationVerifier verifier =
      new AndroidSafetyNetAttestationVerifier();

  @Test
  void verifies_valid_safetynet_attestation_non_strict() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());
    byte[] clientDataHash = sha256(f.clientDataJson());

    AttestationResult result = verifier.verify(obj, clientDataHash, null);

    assertThat(result.format()).isEqualTo("android-safetynet");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void rejects_when_nonce_does_not_match() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withTamperedNonce("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_cts_profile_match_false() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withCtsProfileMatch(false, "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_leaf_cert_san_is_not_attest_android_com() throws Exception {
    SafetyNetFixture f = SafetyNetFixture.withLeafSan("evil.example.com", "example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }
}
```

`SafetyNetFixture`는 Task 5의 `AttestationTestCerts`에서 BouncyCastle로 self-signed cert chain + nimbus로 JWS 서명한 response를 빌드하는 헬퍼다. Task 1에서는 일단 같은 파일 안에 인라인으로 둔다 (Task 5에서 추출).

- [ ] **Step 2: 테스트 실패 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AndroidSafetyNetAttestationVerifierTest" -i`
Expected: FAIL with `AndroidSafetyNetAttestationVerifier not found` 또는 컴파일 에러.

- [ ] **Step 3: sealed `permits`에 신규 verifier 추가**

`AttestationVerifier.java`:

```java
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier,
        PackedAttestationVerifier,
        AppleAnonymousAttestationVerifier,
        AndroidKeyAttestationVerifier,
        AndroidSafetyNetAttestationVerifier {

  String format();

  AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException;
}
```

- [ ] **Step 4: `AndroidSafetyNetAttestationVerifier` 구현**

`AndroidSafetyNetAttestationVerifier.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code android-safetynet} attestation format (WebAuthn L3 §8.5). The attestation statement
 * carries {@code ver} and {@code response} — a SafetyNet attestation JWS. Verification:
 *
 * <ol>
 *   <li>Parse {@code response} as a JWS. The leaf certificate in the {@code x5c} JWS header is the
 *       AndroidAttest cert; verify the JWS RSA signature with its public key.
 *   <li>Verify the leaf certificate's subject alternative name is {@code attest.android.com}.
 *   <li>Decode the JWS payload as JSON; require {@code nonce == base64(SHA-256(authenticatorData ||
 *       clientDataHash))}, {@code ctsProfileMatch == true}, {@code basicIntegrity == true}.
 *   <li>Strict mode: validate the JWS x5c chain to an MDS trust anchor for the credential's AAGUID
 *       (often the zero AAGUID for SafetyNet — verifier accepts whatever the MDS entry holds).
 * </ol>
 */
public final class AndroidSafetyNetAttestationVerifier implements AttestationVerifier {

  private static final String EXPECTED_LEAF_SAN = "attest.android.com";

  @Override
  public String format() {
    return "android-safetynet";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object responseObj = attStmt.get("response");
      if (!(responseObj instanceof byte[] responseBytes)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet attestation missing response");
      }
      String jwsCompact = new String(responseBytes, StandardCharsets.UTF_8);
      JWSObject jws;
      try {
        jws = JWSObject.parse(jwsCompact);
      } catch (java.text.ParseException e) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet response is not a parseable JWS: " + e.getMessage());
      }

      List<X509Certificate> chain = parseX5c(jws);
      if (chain.isEmpty()) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet JWS has no x5c chain");
      }
      X509Certificate leaf = chain.get(0);
      if (!leafSanMatches(leaf, EXPECTED_LEAF_SAN)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet leaf cert SAN must be " + EXPECTED_LEAF_SAN);
      }
      if (!jws.verify(new RSASSAVerifier((java.security.interfaces.RSAPublicKey) leaf.getPublicKey()))) {
        throw new Fido2VerificationException(
            FailureReason.SIGNATURE_INVALID, "android-safetynet JWS signature invalid");
      }

      JWTClaimsSet claims;
      try {
        claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());
      } catch (java.text.ParseException e) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet JWS payload is not a JSON object: " + e.getMessage());
      }
      String nonce = claims.getStringClaim("nonce");
      if (nonce == null) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet payload missing nonce");
      }
      ByteArrayOutputStream nonceInput = new ByteArrayOutputStream();
      nonceInput.writeBytes(attestationObject.authenticatorData().rawBytes());
      nonceInput.writeBytes(clientDataHash);
      byte[] expectedNonce = MessageDigest.getInstance("SHA-256").digest(nonceInput.toByteArray());
      byte[] actualNonce = java.util.Base64.getDecoder().decode(nonce);
      if (!MessageDigest.isEqual(expectedNonce, actualNonce)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "android-safetynet nonce does not match SHA-256(authData || clientDataHash)");
      }
      Boolean ctsProfileMatch = claims.getBooleanClaim("ctsProfileMatch");
      if (!Boolean.TRUE.equals(ctsProfileMatch)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet ctsProfileMatch is not true");
      }
      Boolean basicIntegrity = claims.getBooleanClaim("basicIntegrity");
      if (!Boolean.TRUE.equals(basicIntegrity)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "android-safetynet basicIntegrity is not true");
      }

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL,
            "android-safetynet attestation has no attested credential");
      }
      if (trustAnchors != null) {
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — safetynet authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "android-safetynet authenticator AAGUID " + aaguid + " is revoked per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "android-safetynet chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("android-safetynet", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (Exception e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "android-safetynet attestation verification failed: " + e.getMessage());
    }
  }

  private static List<X509Certificate> parseX5c(JWSObject jws) throws Exception {
    Collection<com.nimbusds.jose.util.Base64> x5c = jws.getHeader().getX509CertChain();
    if (x5c == null) {
      return List.of();
    }
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<X509Certificate> chain = new ArrayList<>();
    for (com.nimbusds.jose.util.Base64 b64 : x5c) {
      chain.add(
          (X509Certificate)
              cf.generateCertificate(new ByteArrayInputStream(b64.decode())));
    }
    return chain;
  }

  private static boolean leafSanMatches(X509Certificate leaf, String expected) throws Exception {
    Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
    if (sans == null) {
      return false;
    }
    for (List<?> entry : sans) {
      // Each SAN entry is [type, value]. Type 2 = dNSName.
      if (entry.size() >= 2 && Objects.equals(entry.get(0), 2)
          && expected.equalsIgnoreCase(String.valueOf(entry.get(1)))) {
        return true;
      }
    }
    return false;
  }

  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
```

- [ ] **Step 5: 레지스트리 등록**

`AttestationVerifiers.java`의 `REGISTRY` 맵에 한 줄 추가:

```java
private static final Map<String, AttestationVerifier> REGISTRY =
    Map.of(
        "none", new NoneAttestationVerifier(),
        "packed", new PackedAttestationVerifier(),
        "apple", new AppleAnonymousAttestationVerifier(),
        "android-key", new AndroidKeyAttestationVerifier(),
        "android-safetynet", new AndroidSafetyNetAttestationVerifier());
```

- [ ] **Step 6: `SafetyNetFixture` 헬퍼 (테스트 파일 내부에 인라인)**

`AndroidSafetyNetAttestationVerifierTest.java`의 같은 파일 안에 package-private record + builder:

```java
record SafetyNetFixture(byte[] attestationObject, byte[] clientDataJson) {

  static SafetyNetFixture valid(String rpId) throws Exception {
    return build(rpId, /*tamperNonce*/ false, /*ctsProfileMatch*/ true, EXPECTED_SAN);
  }

  static SafetyNetFixture withTamperedNonce(String rpId) throws Exception {
    return build(rpId, true, true, EXPECTED_SAN);
  }

  static SafetyNetFixture withCtsProfileMatch(boolean v, String rpId) throws Exception {
    return build(rpId, false, v, EXPECTED_SAN);
  }

  static SafetyNetFixture withLeafSan(String san, String rpId) throws Exception {
    return build(rpId, false, true, san);
  }

  private static final String EXPECTED_SAN = "attest.android.com";

  private static SafetyNetFixture build(String rpId, boolean tamperNonce, boolean cts, String san)
      throws Exception {
    // 1. EC P-256 credential key. 2. Build authData with that key in attestedCredentialData.
    // 3. Build clientDataJSON with origin "https://" + rpId + "/" and challenge.
    // 4. Compute nonce = base64(SHA-256(authData || clientDataHash)); if tamperNonce, flip last byte.
    // 5. BouncyCastle: generate RSA-2048 SafetyNet leaf cert with SAN dNSName = san.
    // 6. nimbus: build JWS RS256 with x5c header [leaf, root] and payload {nonce, ctsProfileMatch,
    //    basicIntegrity, timestampMs}.
    // 7. CBOR-encode AttestationObject { fmt: "android-safetynet", attStmt: { ver: "...",
    //    response: <jwsCompact bytes> }, authData }.
    ...
  }
}
```

빌더 본문은 Phase 3의 `Fido2Fixtures`·`Apple verifier 테스트`와 같은 패턴이라 그쪽을 참고해 작성. Task 5에서 `AttestationTestCerts`로 추출한다.

- [ ] **Step 7: 테스트 통과 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AndroidSafetyNetAttestationVerifierTest" -i`
Expected: PASS — 4 tests.

- [ ] **Step 8: `./gradlew check` 전체 실행 (ArchUnit Rule 7 포함)**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. ArchUnit Rule 7은 `nimbus-jose-jwt` import를 이미 허용하고 있으므로 `AndroidSafetyNetAttestationVerifier`의 nimbus 사용은 허용된다.

- [ ] **Step 9: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/fido2/attestation/AndroidSafetyNetAttestationVerifier.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java \
        server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AndroidSafetyNetAttestationVerifierTest.java
git commit -m "feat(fido2): AndroidSafetyNetAttestationVerifier + 레지스트리 등록"
```

---

## Task 2: `FidoU2fAttestationVerifier`

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/FidoU2fAttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java` (sealed `permits`에 추가)
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java` (레지스트리 등록)
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/FidoU2fAttestationVerifierTest.java`

WebAuthn L3 §8.6 (fido-u2f). 레거시 U2F 키들의 마이그레이션 경로. signedData 포맷:
`0x00 (1B) || rpIdHash (32B) || clientDataHash (32B) || credentialId (variable) || publicKeyU2F (65B)` 인데 `publicKeyU2F = 0x04 || x (32B) || y (32B)` — credential COSE 키에서 추출한 비압축 EC P-256 좌표.

- [ ] **Step 1: 실패 테스트 작성 — happy path**

`FidoU2fAttestationVerifierTest.java`:

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.FidoU2fAttestationVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

class FidoU2fAttestationVerifierTest {

  private final FidoU2fAttestationVerifier verifier = new FidoU2fAttestationVerifier();

  @Test
  void verifies_valid_u2f_attestation_non_strict() throws Exception {
    U2fFixture f = U2fFixture.valid("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    AttestationResult result =
        verifier.verify(obj, sha256(f.clientDataJson()), null);

    assertThat(result.format()).isEqualTo("fido-u2f");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void rejects_when_signature_does_not_match() throws Exception {
    U2fFixture f = U2fFixture.withTamperedSignature("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.SIGNATURE_INVALID);
  }

  @Test
  void rejects_non_ec_credential_key() throws Exception {
    U2fFixture f = U2fFixture.withRsaCredentialKey("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.FidoU2fAttestationVerifierTest" -i`
Expected: FAIL — 컴파일 에러.

- [ ] **Step 3: sealed `permits`에 추가**

`AttestationVerifier.java`:

```java
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier,
        PackedAttestationVerifier,
        AppleAnonymousAttestationVerifier,
        AndroidKeyAttestationVerifier,
        AndroidSafetyNetAttestationVerifier,
        FidoU2fAttestationVerifier {
```

- [ ] **Step 4: `FidoU2fAttestationVerifier` 구현**

`FidoU2fAttestationVerifier.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code fido-u2f} attestation format (WebAuthn L3 §8.6). Legacy U2F authenticators. The
 * attestation statement carries {@code sig} and {@code x5c}. Verification:
 *
 * <ol>
 *   <li>Require the credential public key to be EC P-256 — the U2F format predates COSE alg
 *       negotiation and only ES256 is defined.
 *   <li>Construct signed data {@code 0x00 || rpIdHash || clientDataHash || credentialId ||
 *       publicKeyU2F} where {@code publicKeyU2F = 0x04 || x || y} (uncompressed EC point).
 *   <li>Verify {@code sig} (SHA256withECDSA) over signed data with x5c[0]'s public key.
 *   <li>Strict mode: validate the chain to an MDS trust anchor for the credential's AAGUID
 *       (typically the zero AAGUID for U2F — the verifier accepts whatever MDS holds).
 * </ol>
 */
public final class FidoU2fAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "fido-u2f";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();
      Object sigObj = attStmt.get("sig");
      Object x5cObj = attStmt.get("x5c");
      if (!(sigObj instanceof byte[] signature)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "fido-u2f attestation missing sig");
      }
      if (!(x5cObj instanceof List<?> x5cList)
          || x5cList.isEmpty()
          || !(x5cList.get(0) instanceof byte[] leafDer)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "fido-u2f attestation missing x5c");
      }
      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL, "fido-u2f attestation has no attested credential");
      }

      CoseKey coseKey = acd.coseKey();
      if (!(coseKey.publicKey() instanceof ECPublicKey ecPub)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "fido-u2f credential key must be EC P-256 (alg ES256); got " + coseKey.publicKey().getAlgorithm());
      }
      byte[] publicKeyU2F = encodeU2fPublicKey(ecPub);

      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.write(0x00);
      signedData.writeBytes(attestationObject.authenticatorData().rpIdHash());
      signedData.writeBytes(clientDataHash);
      signedData.writeBytes(acd.credentialId());
      signedData.writeBytes(publicKeyU2F);

      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate leaf =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(leafDer));
      Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(leaf.getPublicKey());
      verifier.update(signedData.toByteArray());
      if (!verifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.SIGNATURE_INVALID, "fido-u2f attestation signature invalid");
      }

      if (trustAnchors != null) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Object o : x5cList) {
          if (!(o instanceof byte[] der)) {
            throw new Fido2VerificationException(
                FailureReason.ATTESTATION_INVALID,
                "fido-u2f x5c element must be DER-encoded certificate");
          }
          chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — U2F authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "fido-u2f authenticator AAGUID " + aaguid + " is revoked per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "fido-u2f chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("fido-u2f", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID,
          "fido-u2f attestation verification failed: " + e.getMessage());
    }
  }

  /** Encode EC P-256 public key as the 65-byte uncompressed form: {@code 0x04 || x(32) || y(32)}. */
  private static byte[] encodeU2fPublicKey(ECPublicKey pub) {
    byte[] x = unsigned32(pub.getW().getAffineX());
    byte[] y = unsigned32(pub.getW().getAffineY());
    byte[] out = new byte[65];
    out[0] = 0x04;
    System.arraycopy(x, 0, out, 1, 32);
    System.arraycopy(y, 0, out, 33, 32);
    return out;
  }

  private static byte[] unsigned32(java.math.BigInteger n) {
    byte[] raw = n.toByteArray();
    if (raw.length == 32) {
      return raw;
    }
    byte[] out = new byte[32];
    if (raw.length == 33 && raw[0] == 0) {
      System.arraycopy(raw, 1, out, 0, 32);
    } else if (raw.length < 32) {
      System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
    } else {
      throw new IllegalArgumentException("EC coordinate too large: " + raw.length + " bytes");
    }
    return out;
  }

  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
```

- [ ] **Step 5: 레지스트리 등록**

`AttestationVerifiers.java`:

```java
private static final Map<String, AttestationVerifier> REGISTRY =
    Map.of(
        "none", new NoneAttestationVerifier(),
        "packed", new PackedAttestationVerifier(),
        "apple", new AppleAnonymousAttestationVerifier(),
        "android-key", new AndroidKeyAttestationVerifier(),
        "android-safetynet", new AndroidSafetyNetAttestationVerifier(),
        "fido-u2f", new FidoU2fAttestationVerifier());
```

- [ ] **Step 6: `U2fFixture` 헬퍼 (인라인)**

`FidoU2fAttestationVerifierTest.java` 같은 파일 내 package-private record + builder. `SafetyNetFixture`와 동일 패턴 — EC P-256 credential key + BouncyCastle self-signed leaf + signedData ECDSA 서명. Task 5에서 `AttestationTestCerts`로 추출.

- [ ] **Step 7: 테스트 통과 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.FidoU2fAttestationVerifierTest" -i`
Expected: PASS — 3 tests.

- [ ] **Step 8: `./gradlew check` 전체 실행**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 9: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/fido2/attestation/FidoU2fAttestationVerifier.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java \
        server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/FidoU2fAttestationVerifierTest.java
git commit -m "feat(fido2): FidoU2fAttestationVerifier + 레지스트리 등록"
```

---

## Task 3: TPM 이진 파서 (`fido2.tpm` 서브패키지)

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/tpm/TpmException.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/tpm/TpmsAttest.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/tpm/TpmtPublic.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/tpm/TpmsAttestTest.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/tpm/TpmtPublicTest.java`

TPM 2.0 명세 (TCG TPM 2.0 Library Part 2, "Structures"). 핵심 구조:

**TPMS_ATTEST** (certInfo의 컨테이너):
```
TPM_GENERATED magic (4B)          == 0xFF544347 ("\xFFTCG")
TPMI_ST_ATTEST type (2B)          == 0x8017 (TPM_ST_ATTEST_CERTIFY)
TPM2B_NAME qualifiedSigner (2B len || bytes)
TPM2B_DATA extraData (2B len || bytes)   ← 우리가 검증할 hash 들어감
TPMS_CLOCK_INFO clockInfo (17B)
UINT64 firmwareVersion (8B)
TPMU_ATTEST attested (TPMS_CERTIFY_INFO when type==CERTIFY)
  TPM2B_NAME name (2B len || bytes)         ← SHA-256(pubArea)
  TPM2B_NAME qualifiedName (2B len || bytes)
```

**TPMT_PUBLIC** (pubArea):
```
TPMI_ALG_PUBLIC type (2B)  — 0x0001=RSA, 0x0023=ECC
TPMI_ALG_HASH nameAlg (2B) — 0x000B=SHA256
TPMA_OBJECT objectAttributes (4B)
TPM2B_DIGEST authPolicy (2B len || bytes)
TPMU_PUBLIC_PARMS parameters — type-dependent
TPMU_PUBLIC_ID unique — RSA: TPM2B_PUBLIC_KEY_RSA (modulus); ECC: TPMS_ECC_POINT (x, y)
```

- [ ] **Step 1: `TpmException` 실패 테스트 작성**

`TpmsAttestTest.java`:

```java
package com.crosscert.passkey.unit.fido2.tpm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.tpm.TpmException;
import com.crosscert.passkey.fido2.tpm.TpmsAttest;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class TpmsAttestTest {

  @Test
  void parses_well_formed_certify_attest() {
    byte[] raw = TpmFixtures.attestCertify(/*extraData*/ new byte[] {1, 2, 3}, /*name*/ new byte[32]);
    TpmsAttest attest = TpmsAttest.parse(raw);
    assertThat(attest.magic()).isEqualTo(0xFF544347);
    assertThat(attest.type()).isEqualTo(0x8017);
    assertThat(attest.extraData()).containsExactly(1, 2, 3);
    assertThat(attest.attestedName()).hasSize(32);
  }

  @Test
  void rejects_wrong_magic() {
    byte[] raw = TpmFixtures.attestCertify(new byte[0], new byte[32]);
    ByteBuffer.wrap(raw).putInt(0, 0xDEADBEEF);
    assertThatThrownBy(() -> TpmsAttest.parse(raw))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("magic");
  }

  @Test
  void rejects_wrong_attest_type() {
    byte[] raw = TpmFixtures.attestCertify(new byte[0], new byte[32]);
    // Overwrite type field with TPM_ST_ATTEST_QUOTE (0x8018) instead of CERTIFY.
    raw[4] = (byte) 0x80;
    raw[5] = (byte) 0x18;
    assertThatThrownBy(() -> TpmsAttest.parse(raw))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("ATTEST_CERTIFY");
  }

  @Test
  void rejects_truncated_length_prefix() {
    byte[] raw = new byte[] {(byte) 0xFF, 0x54, 0x43, 0x47, (byte) 0x80, 0x17};
    assertThatThrownBy(() -> TpmsAttest.parse(raw)).isInstanceOf(TpmException.class);
  }
}
```

`TpmFixtures`는 같은 테스트 패키지에 둔다 (`server/src/test/java/com/crosscert/passkey/unit/fido2/tpm/TpmFixtures.java`):

```java
package com.crosscert.passkey.unit.fido2.tpm;

import java.nio.ByteBuffer;

final class TpmFixtures {
  private TpmFixtures() {}

  /** Build a minimal valid TPMS_ATTEST (TPM_ST_ATTEST_CERTIFY) for testing. */
  static byte[] attestCertify(byte[] extraData, byte[] attestedName) {
    // magic(4) + type(2) + qSignerLen(2)=0 + extraLen(2)+extra + clock(17) + fwVer(8)
    //   + nameLen(2)+name + qNameLen(2)=0
    int len = 4 + 2 + 2 + 2 + extraData.length + 17 + 8 + 2 + attestedName.length + 2;
    ByteBuffer buf = ByteBuffer.allocate(len);
    buf.putInt(0xFF544347);                       // magic
    buf.putShort((short) 0x8017);                 // type CERTIFY
    buf.putShort((short) 0);                      // qualifiedSigner empty
    buf.putShort((short) extraData.length);
    buf.put(extraData);
    buf.put(new byte[17]);                        // clockInfo (don't care)
    buf.putLong(0L);                              // firmwareVersion
    buf.putShort((short) attestedName.length);
    buf.put(attestedName);
    buf.putShort((short) 0);                      // qualifiedName empty
    return buf.array();
  }

  /** Build a minimal TPMT_PUBLIC for RSA 2048. */
  static byte[] publicRsa2048(byte[] modulus) {
    // type(2)=0x0001 + nameAlg(2)=0x000B + objectAttributes(4) + authPolicy len(2)=0
    //   + parameters: symmetric(2)=0x0010 NULL + scheme(2)=0x0010 NULL + keyBits(2)=2048 + exponent(4)
    //   + unique RSA modulus: len(2) + bytes
    int paramsLen = 2 + 2 + 2 + 4;
    int len = 2 + 2 + 4 + 2 + paramsLen + 2 + modulus.length;
    ByteBuffer buf = ByteBuffer.allocate(len);
    buf.putShort((short) 0x0001);   // TPM_ALG_RSA
    buf.putShort((short) 0x000B);   // TPM_ALG_SHA256
    buf.putInt(0x00050072);         // objectAttributes (sign+restricted+...) — not validated here
    buf.putShort((short) 0);        // authPolicy empty
    buf.putShort((short) 0x0010);   // symmetric NULL
    buf.putShort((short) 0x0010);   // scheme NULL
    buf.putShort((short) 2048);     // keyBits
    buf.putInt(0x00010001);         // exponent = 65537
    buf.putShort((short) modulus.length);
    buf.put(modulus);
    return buf.array();
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.tpm.TpmsAttestTest"`
Expected: FAIL — 컴파일 에러.

- [ ] **Step 3: `TpmException` 구현**

`TpmException.java`:

```java
package com.crosscert.passkey.fido2.tpm;

/**
 * TPM 2.0 structure parsing/consistency failure. Unchecked — the verifier wraps it in {@code
 * Fido2VerificationException(INVALID_TPM_STRUCTURE)} so the boundary contract (the {@code fido2}
 * core throws only {@code Fido2VerificationException}) is preserved.
 */
public class TpmException extends RuntimeException {
  public TpmException(String message) {
    super(message);
  }

  public TpmException(String message, Throwable cause) {
    super(message, cause);
  }
}
```

- [ ] **Step 4: `TpmsAttest` 구현**

`TpmsAttest.java`:

```java
package com.crosscert.passkey.fido2.tpm;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * The TPM 2.0 {@code TPMS_ATTEST} structure parsed from the {@code certInfo} field of a TPM
 * attestation statement. Only {@code TPM_ST_ATTEST_CERTIFY} (0x8017) is supported — that is the
 * only attest type WebAuthn's tpm format uses.
 *
 * <p>Spec: TCG TPM 2.0 Library Part 2 §10.12, §10.13. Field layout:
 *
 * <pre>
 *   TPM_GENERATED magic           (4B big-endian, must equal 0xFF544347 == "\xFFTCG")
 *   TPMI_ST_ATTEST type           (2B BE, must equal 0x8017 == TPM_ST_ATTEST_CERTIFY)
 *   TPM2B_NAME qualifiedSigner    (2B BE length || bytes)
 *   TPM2B_DATA extraData          (2B BE length || bytes)
 *   TPMS_CLOCK_INFO clockInfo     (17B — opaque to us)
 *   UINT64 firmwareVersion        (8B BE — opaque)
 *   TPMS_CERTIFY_INFO attested    (TPM2B_NAME name || TPM2B_NAME qualifiedName)
 * </pre>
 */
public record TpmsAttest(
    int magic,
    int type,
    byte[] qualifiedSigner,
    byte[] extraData,
    long firmwareVersion,
    byte[] attestedName,
    byte[] attestedQualifiedName) {

  public static final int TPM_GENERATED_VALUE = 0xFF544347;
  public static final int TPM_ST_ATTEST_CERTIFY = 0x8017;

  public static TpmsAttest parse(byte[] raw) {
    try {
      ByteBuffer buf = ByteBuffer.wrap(raw); // big-endian by default
      int magic = buf.getInt();
      if (magic != TPM_GENERATED_VALUE) {
        throw new TpmException(
            "TPMS_ATTEST magic is not TPM_GENERATED_VALUE (got 0x" + Integer.toHexString(magic) + ")");
      }
      int type = Short.toUnsignedInt(buf.getShort());
      if (type != TPM_ST_ATTEST_CERTIFY) {
        throw new TpmException(
            "TPMS_ATTEST type is not TPM_ST_ATTEST_CERTIFY (got 0x" + Integer.toHexString(type) + ")");
      }
      byte[] qualifiedSigner = readSized(buf, "qualifiedSigner");
      byte[] extraData = readSized(buf, "extraData");
      // Skip clockInfo (17 bytes: UINT64 clock + UINT32 resetCount + UINT32 restartCount + UINT8 safe).
      if (buf.remaining() < 17) {
        throw new TpmException("TPMS_ATTEST clockInfo truncated");
      }
      buf.position(buf.position() + 17);
      long firmwareVersion = buf.getLong();
      byte[] attestedName = readSized(buf, "attestedName");
      byte[] attestedQualifiedName = readSized(buf, "attestedQualifiedName");
      if (buf.hasRemaining()) {
        throw new TpmException(
            "TPMS_ATTEST has " + buf.remaining() + " trailing bytes — malformed");
      }
      return new TpmsAttest(
          magic, type, qualifiedSigner, extraData, firmwareVersion, attestedName, attestedQualifiedName);
    } catch (BufferUnderflowException e) {
      throw new TpmException("TPMS_ATTEST truncated", e);
    }
  }

  private static byte[] readSized(ByteBuffer buf, String fieldName) {
    if (buf.remaining() < 2) {
      throw new TpmException("TPMS_ATTEST " + fieldName + " length prefix truncated");
    }
    int len = Short.toUnsignedInt(buf.getShort());
    if (buf.remaining() < len) {
      throw new TpmException(
          "TPMS_ATTEST " + fieldName + " truncated (declared " + len + ", remaining " + buf.remaining() + ")");
    }
    byte[] out = new byte[len];
    buf.get(out);
    return out;
  }
}
```

- [ ] **Step 5: `TpmsAttest` 테스트 통과 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.tpm.TpmsAttestTest"`
Expected: PASS — 4 tests.

- [ ] **Step 6: `TpmtPublic` 실패 테스트 작성**

`TpmtPublicTest.java`:

```java
package com.crosscert.passkey.unit.fido2.tpm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.tpm.TpmException;
import com.crosscert.passkey.fido2.tpm.TpmtPublic;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.Test;

class TpmtPublicTest {

  @Test
  void parses_rsa_2048_public_area_and_reconstructs_key() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair pair = gen.generateKeyPair();
    RSAPublicKey expected = (RSAPublicKey) pair.getPublic();

    byte[] modulus = unsignedBytes(expected.getModulus(), 256);
    byte[] pubArea = TpmFixtures.publicRsa2048(modulus);

    TpmtPublic pub = TpmtPublic.parse(pubArea);
    assertThat(pub.type()).isEqualTo(0x0001);
    assertThat(pub.nameAlg()).isEqualTo(0x000B);
    RSAPublicKey reconstructed = (RSAPublicKey) pub.publicKey();
    assertThat(reconstructed.getModulus()).isEqualTo(expected.getModulus());
    assertThat(reconstructed.getPublicExponent()).isEqualTo(BigInteger.valueOf(65537));
  }

  @Test
  void rejects_unknown_alg_type() {
    byte[] pubArea = TpmFixtures.publicRsa2048(new byte[256]);
    pubArea[0] = 0x00;
    pubArea[1] = 0x10; // unknown alg
    assertThatThrownBy(() -> TpmtPublic.parse(pubArea))
        .isInstanceOf(TpmException.class)
        .hasMessageContaining("unsupported");
  }

  private static byte[] unsignedBytes(BigInteger n, int len) {
    byte[] raw = n.toByteArray();
    if (raw.length == len) return raw;
    if (raw.length == len + 1 && raw[0] == 0) {
      byte[] out = new byte[len];
      System.arraycopy(raw, 1, out, 0, len);
      return out;
    }
    if (raw.length < len) {
      byte[] out = new byte[len];
      System.arraycopy(raw, 0, out, len - raw.length, raw.length);
      return out;
    }
    throw new IllegalArgumentException("too large");
  }
}
```

- [ ] **Step 7: `TpmtPublic` 구현**

`TpmtPublic.java`:

```java
package com.crosscert.passkey.fido2.tpm;

import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * The TPM 2.0 {@code TPMT_PUBLIC} structure parsed from the {@code pubArea} field of a TPM
 * attestation statement. Only the {@code RSA} (0x0001) and {@code ECC} (0x0023) algorithm types
 * are supported — those are the only ones in use by WebAuthn tpm authenticators.
 *
 * <p>Spec: TCG TPM 2.0 Library Part 2 §12.2.4.
 */
public record TpmtPublic(int type, int nameAlg, PublicKey publicKey) {

  public static final int TPM_ALG_RSA = 0x0001;
  public static final int TPM_ALG_ECC = 0x0023;

  public static TpmtPublic parse(byte[] raw) {
    try {
      ByteBuffer buf = ByteBuffer.wrap(raw);
      int type = Short.toUnsignedInt(buf.getShort());
      int nameAlg = Short.toUnsignedInt(buf.getShort());
      buf.getInt(); // objectAttributes — not validated here (verifier may add policy later)
      skipSized(buf, "authPolicy");
      PublicKey publicKey =
          switch (type) {
            case TPM_ALG_RSA -> parseRsaParametersAndUnique(buf);
            case TPM_ALG_ECC -> parseEccParametersAndUnique(buf);
            default ->
                throw new TpmException(
                    "TPMT_PUBLIC unsupported type 0x" + Integer.toHexString(type));
          };
      if (buf.hasRemaining()) {
        throw new TpmException("TPMT_PUBLIC has " + buf.remaining() + " trailing bytes");
      }
      return new TpmtPublic(type, nameAlg, publicKey);
    } catch (BufferUnderflowException e) {
      throw new TpmException("TPMT_PUBLIC truncated", e);
    }
  }

  private static PublicKey parseRsaParametersAndUnique(ByteBuffer buf) {
    int symmetric = Short.toUnsignedInt(buf.getShort());
    int scheme = Short.toUnsignedInt(buf.getShort());
    int keyBits = Short.toUnsignedInt(buf.getShort());
    long exponent = Integer.toUnsignedLong(buf.getInt());
    if (exponent == 0L) {
      exponent = 65537L; // TPM spec: 0 means "use the default public exponent of 65537".
    }
    byte[] modulus = readSized(buf, "RSA modulus");
    if (modulus.length * 8 != keyBits) {
      throw new TpmException(
          "TPMT_PUBLIC RSA modulus length (" + (modulus.length * 8) + " bits) != keyBits " + keyBits);
    }
    try {
      RSAPublicKeySpec spec =
          new RSAPublicKeySpec(new BigInteger(1, modulus), BigInteger.valueOf(exponent));
      return KeyFactory.getInstance("RSA").generatePublic(spec);
    } catch (Exception e) {
      throw new TpmException("TPMT_PUBLIC RSA key reconstruction failed", e);
    }
  }

  private static PublicKey parseEccParametersAndUnique(ByteBuffer buf) {
    int symmetric = Short.toUnsignedInt(buf.getShort());
    int scheme = Short.toUnsignedInt(buf.getShort());
    int curveId = Short.toUnsignedInt(buf.getShort());
    int kdf = Short.toUnsignedInt(buf.getShort());
    // TPM_ECC_NIST_P256 = 0x0003 — the only curve WebAuthn tpm uses in practice.
    if (curveId != 0x0003) {
      throw new TpmException(
          "TPMT_PUBLIC ECC unsupported curve 0x" + Integer.toHexString(curveId));
    }
    byte[] x = readSized(buf, "ECC x");
    byte[] y = readSized(buf, "ECC y");
    try {
      java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
      params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
      java.security.spec.ECParameterSpec ecSpec =
          params.getParameterSpec(java.security.spec.ECParameterSpec.class);
      ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
      return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, ecSpec));
    } catch (Exception e) {
      throw new TpmException("TPMT_PUBLIC ECC key reconstruction failed", e);
    }
  }

  private static byte[] readSized(ByteBuffer buf, String fieldName) {
    if (buf.remaining() < 2) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " length prefix truncated");
    }
    int len = Short.toUnsignedInt(buf.getShort());
    if (buf.remaining() < len) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " truncated");
    }
    byte[] out = new byte[len];
    buf.get(out);
    return out;
  }

  private static void skipSized(ByteBuffer buf, String fieldName) {
    if (buf.remaining() < 2) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " length prefix truncated");
    }
    int len = Short.toUnsignedInt(buf.getShort());
    if (buf.remaining() < len) {
      throw new TpmException("TPMT_PUBLIC " + fieldName + " truncated");
    }
    buf.position(buf.position() + len);
  }
}
```

- [ ] **Step 8: `TpmtPublic` 테스트 통과 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.tpm.TpmtPublicTest"`
Expected: PASS — 2 tests.

- [ ] **Step 9: `./gradlew check` 전체 + ArchUnit Rule 7 확인**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. `fido2.tpm`은 java.* + 자체 `fido2.tpm` 패키지만 사용 — Rule 7 통과.

- [ ] **Step 10: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/fido2/tpm/ \
        server/src/test/java/com/crosscert/passkey/unit/fido2/tpm/
git commit -m "feat(fido2): fido2.tpm 서브패키지 — TPMS_ATTEST/TPMT_PUBLIC 이진 파서"
```

---

## Task 4: `TpmAttestationVerifier` (TPM 2.0 only)

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/TpmAttestationVerifier.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java` (FailureReason 추가)
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java` (sealed permits)
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java` (레지스트리)
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/TpmAttestationVerifierTest.java`

- [ ] **Step 1: `FailureReason` 신규 값 추가**

`Fido2VerificationException.java`의 enum:

```java
public enum FailureReason {
  MALFORMED_CBOR,
  MALFORMED_CLIENT_DATA,
  WRONG_CEREMONY_TYPE,
  CHALLENGE_MISMATCH,
  ORIGIN_MISMATCH,
  RPID_HASH_MISMATCH,
  UP_FLAG_MISSING,
  UV_FLAG_REQUIRED,
  NO_ATTESTED_CREDENTIAL,
  UNSUPPORTED_ALGORITHM,
  UNSUPPORTED_ATTESTATION_FORMAT,
  /** The attestation statement is structurally invalid or contradicts policy (e.g. tpm ver=1.2). */
  INVALID_ATTESTATION_FORMAT,
  /** A TPM 2.0 structure (TPMS_ATTEST / TPMT_PUBLIC) failed to parse or was internally inconsistent. */
  INVALID_TPM_STRUCTURE,
  ATTESTATION_INVALID,
  SIGNATURE_INVALID,
  TRUST_PATH_INVALID,
  MDS_TRUST_FAILED,
  AUTHENTICATOR_REVOKED
}
```

- [ ] **Step 2: 실패 테스트 작성**

`TpmAttestationVerifierTest.java`:

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.TpmAttestationVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

class TpmAttestationVerifierTest {

  private final TpmAttestationVerifier verifier = new TpmAttestationVerifier();

  @Test
  void verifies_valid_tpm2_rsa_attestation_non_strict() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), null);

    assertThat(result.format()).isEqualTo("tpm");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void verifies_valid_tpm2_ecc_attestation_non_strict() throws Exception {
    TpmFixture f = TpmFixture.validEcc("example.com");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    AttestationResult result = verifier.verify(obj, sha256(f.clientDataJson()), null);

    assertThat(result.format()).isEqualTo("tpm");
  }

  @Test
  void rejects_tpm_1_2_with_invalid_attestation_format() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withVer("1.2");
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.INVALID_ATTESTATION_FORMAT);
  }

  @Test
  void rejects_when_pubarea_does_not_match_credential_key() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withMismatchedPubArea();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_extra_data_does_not_match_hash() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withTamperedExtraData();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_attested_name_does_not_match_pubarea_hash() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withTamperedAttestedName();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void rejects_when_aik_cert_missing_eku() throws Exception {
    TpmFixture f = TpmFixture.validRsa("example.com").withoutAikEku();
    AttestationObject obj = AttestationObject.parse(f.attestationObject());

    assertThatThrownBy(() -> verifier.verify(obj, sha256(f.clientDataJson()), null))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }
}
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.TpmAttestationVerifierTest"`
Expected: FAIL — `TpmAttestationVerifier not found`.

- [ ] **Step 4: sealed `permits`에 추가**

`AttestationVerifier.java`:

```java
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier,
        PackedAttestationVerifier,
        AppleAnonymousAttestationVerifier,
        AndroidKeyAttestationVerifier,
        AndroidSafetyNetAttestationVerifier,
        FidoU2fAttestationVerifier,
        TpmAttestationVerifier {
```

- [ ] **Step 5: `TpmAttestationVerifier` 구현**

`TpmAttestationVerifier.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import com.crosscert.passkey.fido2.mds.MetadataEntry;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.tpm.TpmException;
import com.crosscert.passkey.fido2.tpm.TpmsAttest;
import com.crosscert.passkey.fido2.tpm.TpmtPublic;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code tpm} attestation format (WebAuthn L3 §8.3). Only TPM 2.0 (attStmt.ver == "2.0") is
 * supported — TPM 1.2 is rejected with {@code INVALID_ATTESTATION_FORMAT}. Verification (6 steps):
 *
 * <ol>
 *   <li>Extract required attStmt fields (ver=2.0, alg, x5c, sig, certInfo, pubArea).
 *   <li>Parse pubArea (TPMT_PUBLIC) and verify the reconstructed public key equals the credential
 *       public key (by JCA {@code PublicKey.equals}).
 *   <li>Parse certInfo (TPMS_ATTEST) and verify magic, type, extraData == SHA-256(authData ||
 *       clientDataHash), and attested.name == SHA-256-prefixed name of pubArea.
 *   <li>Verify sig over certInfo with the AIK certificate's public key.
 *   <li>Verify AIK certificate is a TPM AIK (v3, basicConstraints CA=false, EKU includes
 *       2.23.133.8.3, SAN includes 2.23.133.2.1/2/3 OIDs, AAGUID extension matches if present).
 *   <li>Strict mode: validate the chain to an MDS trust anchor.
 * </ol>
 */
public final class TpmAttestationVerifier implements AttestationVerifier {

  /** AIK Extended Key Usage OID — id-fido-gen-ce-aaguid is the AAGUID extension. */
  private static final String TPM_AIK_EKU_OID = "2.23.133.8.3";

  /** SAN OID prefix for TPM-issued certs: 2.23.133.2.{1,2,3} = manufacturer/model/version. */
  private static final String TPM_SAN_OID_PREFIX = "2.23.133.2.";

  /** id-fido-gen-ce-aaguid — same extension as packed format's AAGUID check. */
  private static final String FIDO_AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4";

  @Override
  public String format() {
    return "tpm";
  }

  @Override
  public AttestationResult verify(
      AttestationObject attestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)
      throws Fido2VerificationException {
    try {
      Map<?, ?> attStmt = attestationObject.attestationStatement();

      // (1) attStmt required fields + ver=2.0.
      Object verObj = attStmt.get("ver");
      if (!"2.0".equals(verObj)) {
        throw new Fido2VerificationException(
            FailureReason.INVALID_ATTESTATION_FORMAT,
            "tpm attestation ver must be \"2.0\" (got " + verObj + ")");
      }
      Object sigObj = attStmt.get("sig");
      Object algObj = attStmt.get("alg");
      Object x5cObj = attStmt.get("x5c");
      Object certInfoObj = attStmt.get("certInfo");
      Object pubAreaObj = attStmt.get("pubArea");
      if (!(sigObj instanceof byte[] signature)
          || !(algObj instanceof Long algValue)
          || !(x5cObj instanceof List<?> x5cList)
          || x5cList.isEmpty()
          || !(x5cList.get(0) instanceof byte[] aikDer)
          || !(certInfoObj instanceof byte[] certInfo)
          || !(pubAreaObj instanceof byte[] pubArea)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "tpm attStmt missing required field(s)");
      }

      AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
      if (acd == null) {
        throw new Fido2VerificationException(
            FailureReason.NO_ATTESTED_CREDENTIAL, "tpm attestation has no attested credential");
      }

      // (2) pubArea ↔ credential public key.
      TpmtPublic pub;
      try {
        pub = TpmtPublic.parse(pubArea);
      } catch (TpmException e) {
        throw new Fido2VerificationException(
            FailureReason.INVALID_TPM_STRUCTURE, "tpm pubArea: " + e.getMessage());
      }
      if (!pub.publicKey().equals(acd.coseKey().publicKey())) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID, "tpm pubArea public key does not match credential key");
      }

      // (3) certInfo: magic / type / extraData / attested.name.
      TpmsAttest attest;
      try {
        attest = TpmsAttest.parse(certInfo);
      } catch (TpmException e) {
        throw new Fido2VerificationException(
            FailureReason.INVALID_TPM_STRUCTURE, "tpm certInfo: " + e.getMessage());
      }
      ByteArrayOutputStream extraExpected = new ByteArrayOutputStream();
      extraExpected.writeBytes(attestationObject.authenticatorData().rawBytes());
      extraExpected.writeBytes(clientDataHash);
      byte[] expectedExtra = MessageDigest.getInstance("SHA-256").digest(extraExpected.toByteArray());
      if (!MessageDigest.isEqual(expectedExtra, attest.extraData())) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm certInfo.extraData does not match SHA-256(authData || clientDataHash)");
      }
      // attested.name = nameAlg(2B) || SHA-256(pubArea)
      byte[] pubAreaHash = MessageDigest.getInstance("SHA-256").digest(pubArea);
      byte[] expectedName = new byte[2 + pubAreaHash.length];
      ByteBuffer.wrap(expectedName).putShort((short) pub.nameAlg()).put(pubAreaHash);
      if (!MessageDigest.isEqual(expectedName, attest.attestedName())) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm certInfo.attested.name does not match nameAlg||SHA-256(pubArea)");
      }

      // (4) Verify sig over certInfo with AIK cert public key.
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate aik = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(aikDer));
      String jcaAlg = jcaAlgorithmForCoseAlg(algValue, aik.getPublicKey());
      Signature sigVerifier = Signature.getInstance(jcaAlg);
      sigVerifier.initVerify(aik.getPublicKey());
      sigVerifier.update(certInfo);
      if (!sigVerifier.verify(signature)) {
        throw new Fido2VerificationException(
            FailureReason.SIGNATURE_INVALID, "tpm certInfo signature invalid");
      }

      // (5) AIK cert compliance.
      verifyAikCertCompliance(aik, acd.aaguid());

      // (6) strict: chain → MDS trust anchor.
      if (trustAnchors != null) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Object o : x5cList) {
          if (!(o instanceof byte[] der)) {
            throw new Fido2VerificationException(
                FailureReason.ATTESTATION_INVALID, "tpm x5c element must be DER cert");
          }
          chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        UUID aaguid = aaguidOf(acd);
        Optional<MetadataEntry> entry = trustAnchors.findEntry(aaguid);
        if (entry.isEmpty()) {
          throw new Fido2VerificationException(
              FailureReason.MDS_TRUST_FAILED,
              "no MDS entry for AAGUID " + aaguid + " — tpm authenticator not in metadata");
        }
        if (entry.get().isRevoked()) {
          throw new Fido2VerificationException(
              FailureReason.AUTHENTICATOR_REVOKED,
              "tpm authenticator AAGUID " + aaguid + " is revoked per MDS");
        }
        if (!AttestationCertPathValidator.validates(chain, trustAnchors.trustAnchors(aaguid))) {
          throw new Fido2VerificationException(
              FailureReason.TRUST_PATH_INVALID,
              "tpm chain does not validate to an MDS trust anchor");
        }
      }
      return new AttestationResult("tpm", trustAnchors != null);
    } catch (Fido2VerificationException e) {
      throw e;
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm attestation verification failed: " + e.getMessage());
    }
  }

  private static void verifyAikCertCompliance(X509Certificate aik, byte[] credentialAaguid)
      throws Fido2VerificationException {
    if (aik.getVersion() != 3) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert must be X.509 v3");
    }
    if (aik.getBasicConstraints() >= 0) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert must have CA=false in basicConstraints");
    }
    List<String> eku;
    try {
      eku = aik.getExtendedKeyUsage();
    } catch (java.security.cert.CertificateParsingException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert EKU is malformed: " + e.getMessage());
    }
    if (eku == null || !eku.contains(TPM_AIK_EKU_OID)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert is missing EKU " + TPM_AIK_EKU_OID);
    }
    // SAN must carry at least one 2.23.133.2.{1,2,3} OID (manufacturer/model/version).
    try {
      java.util.Collection<List<?>> sans = aik.getSubjectAlternativeNames();
      boolean haveTpmSan = false;
      if (sans != null) {
        for (List<?> entry : sans) {
          if (entry.size() >= 2) {
            String value = String.valueOf(entry.get(1));
            if (value.contains(TPM_SAN_OID_PREFIX)) {
              haveTpmSan = true;
              break;
            }
          }
        }
      }
      if (!haveTpmSan) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm AIK cert SAN must contain a TPM manufacturer/model/version OID (" + TPM_SAN_OID_PREFIX + "*)");
      }
    } catch (java.security.cert.CertificateParsingException e) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "tpm AIK cert SAN is malformed: " + e.getMessage());
    }
    // FIDO AAGUID extension (optional in tpm). When present, must equal credential's AAGUID.
    byte[] aaguidExt = aik.getExtensionValue(FIDO_AAGUID_EXTENSION_OID);
    if (aaguidExt != null) {
      byte[] inner = DerUtil.unwrapOctetString(aaguidExt, "tpm AIK AAGUID outer OCTET STRING");
      byte[] declared = DerUtil.unwrapOctetString(inner, "tpm AIK AAGUID inner OCTET STRING");
      if (!MessageDigest.isEqual(declared, credentialAaguid)) {
        throw new Fido2VerificationException(
            FailureReason.ATTESTATION_INVALID,
            "tpm AIK cert AAGUID extension does not match credential AAGUID");
      }
    }
  }

  private static String jcaAlgorithmForCoseAlg(long coseAlg, PublicKey aikKey)
      throws Fido2VerificationException {
    // COSE alg values used by tpm: -7 ES256, -257 RS256, -65535 RS1 (legacy, reject).
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default ->
          throw new Fido2VerificationException(
              FailureReason.UNSUPPORTED_ALGORITHM, "tpm attestation unsupported alg: " + coseAlg);
    };
  }

  private static UUID aaguidOf(AttestedCredentialData acd) {
    ByteBuffer buf = ByteBuffer.wrap(acd.aaguid());
    return new UUID(buf.getLong(), buf.getLong());
  }
}
```

- [ ] **Step 6: 레지스트리 등록**

`AttestationVerifiers.java`:

```java
private static final Map<String, AttestationVerifier> REGISTRY =
    Map.ofEntries(
        Map.entry("none", new NoneAttestationVerifier()),
        Map.entry("packed", new PackedAttestationVerifier()),
        Map.entry("apple", new AppleAnonymousAttestationVerifier()),
        Map.entry("android-key", new AndroidKeyAttestationVerifier()),
        Map.entry("android-safetynet", new AndroidSafetyNetAttestationVerifier()),
        Map.entry("fido-u2f", new FidoU2fAttestationVerifier()),
        Map.entry("tpm", new TpmAttestationVerifier()));
```

(`Map.of` 7-pair 한도 초과 시 `Map.ofEntries`로 전환)

- [ ] **Step 7: `TpmFixture` 헬퍼 (인라인)**

`TpmAttestationVerifierTest.java` 같은 파일 내 record + builder. RSA 2048 / EC P-256 키쌍 → TPMT_PUBLIC + TPMS_ATTEST 바이너리 조립 + BouncyCastle AIK self-signed cert (EKU `2.23.133.8.3`, SAN dirName `2.23.133.2.1=manufacturer:id:XYZ` 등). 각 mutator(`withVer`, `withMismatchedPubArea`, `withTamperedExtraData`, `withTamperedAttestedName`, `withoutAikEku`)는 마지막 단계에서 해당 필드만 바꿔 재서명. Task 5에서 `AttestationTestCerts`로 추출.

- [ ] **Step 8: 테스트 통과 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.TpmAttestationVerifierTest"`
Expected: PASS — 7 tests.

- [ ] **Step 9: `./gradlew check` 전체 실행**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 10: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/TpmAttestationVerifier.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java \
        server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/TpmAttestationVerifierTest.java
git commit -m "feat(fido2): TpmAttestationVerifier (TPM 2.0) + FailureReason 2종 추가"
```

---

## Task 5: 테스트 헬퍼 추출 + `DerUtilTest` + FQN 정리

**Files:**
- Create: `server/src/test/java/com/crosscert/passkey/unit/fido2/AttestationTestCerts.java`
- Create: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/DerUtilTest.java`
- Modify: 기존 `Apple/AndroidKey/Packed/Safetynet/U2f/Tpm` verifier 테스트 — 인라인 헬퍼를 `AttestationTestCerts`로 교체, FQN(`com.crosscert.passkey.fido2.mds.*`) → 정식 import 정리

`AttestationTestCerts`로 추출할 공통 메서드:
- `selfSignedCa(String subject, KeyPair caKey)` → `X509Certificate`
- `leafSignedBy(X509Certificate ca, KeyPair caKey, KeyPair leafKey, String subject, java.util.List<Extension> exts)` → `X509Certificate`
- `aaguidExtension(byte[] aaguid)` → `Extension` (FIDO id-fido-gen-ce-aaguid OCTET STRING wrapping)
- `tpmEkuExtension()` / `tpmSanExtension(String manufacturer, String model, String version)`
- `attestationObjectCbor(String fmt, Map<String, Object> attStmt, byte[] authData)` → `byte[]`
- `authData(String rpId, int flags, int signCount, byte[] aaguid, byte[] credentialId, byte[] coseKey)` → `byte[]`

- [ ] **Step 1: 실패 테스트 작성 — `DerUtilTest`**

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.DerUtil;
import org.junit.jupiter.api.Test;

class DerUtilTest {

  @Test
  void unwrap_octet_string_short_form() throws Exception {
    // OCTET STRING, length 3, content [0xAA 0xBB 0xCC]
    byte[] der = {0x04, 0x03, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC};
    assertThat(DerUtil.unwrapOctetString(der, "test")).containsExactly(0xAA, 0xBB, 0xCC);
  }

  @Test
  void unwrap_octet_string_long_form_0x81() throws Exception {
    // OCTET STRING, length 200 via 0x81 long-form
    byte[] content = new byte[200];
    for (int i = 0; i < 200; i++) content[i] = (byte) (i & 0xff);
    byte[] der = new byte[3 + 200];
    der[0] = 0x04;
    der[1] = (byte) 0x81;
    der[2] = (byte) 200;
    System.arraycopy(content, 0, der, 3, 200);
    assertThat(DerUtil.unwrapOctetString(der, "test")).containsExactly(toIntArray(content));
  }

  @Test
  void unwrap_rejects_wrong_tag() {
    byte[] der = {0x30, 0x02, 0x00, 0x00}; // SEQUENCE instead of OCTET STRING
    assertThatThrownBy(() -> DerUtil.unwrapOctetString(der, "outer"))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void unwrap_rejects_unsupported_long_form_0x82() {
    byte[] der = {0x04, (byte) 0x82, 0x00, 0x02, 0x00, 0x00};
    assertThatThrownBy(() -> DerUtil.unwrapOctetString(der, "outer"))
        .isInstanceOf(Fido2VerificationException.class)
        .hasMessageContaining("unsupported");
  }

  @Test
  void extract_apple_nonce_round_trip() throws Exception {
    byte[] nonce = "01234567890123456789012345678901".getBytes();
    // Build SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
    byte[] octet = concat(new byte[] {0x04, (byte) nonce.length}, nonce);
    byte[] ctx = concat(new byte[] {(byte) 0xA1, (byte) octet.length}, octet);
    byte[] seq = concat(new byte[] {0x30, (byte) ctx.length}, ctx);
    assertThat(DerUtil.extractAppleNonce(seq)).isEqualTo(nonce);
  }

  @Test
  void extract_android_key_attestation_challenge_index_4() throws Exception {
    // SEQUENCE { INTEGER 0, INTEGER 0, INTEGER 0, INTEGER 0, OCTET STRING challenge }
    byte[] challenge = "android-challenge".getBytes();
    byte[][] elements = {
        {0x02, 0x01, 0x00}, // INTEGER 0
        {0x02, 0x01, 0x00},
        {0x02, 0x01, 0x00},
        {0x02, 0x01, 0x00},
        concat(new byte[] {0x04, (byte) challenge.length}, challenge),
    };
    int total = 0;
    for (byte[] e : elements) total += e.length;
    byte[] content = new byte[total];
    int off = 0;
    for (byte[] e : elements) {
      System.arraycopy(e, 0, content, off, e.length);
      off += e.length;
    }
    byte[] seq = concat(new byte[] {0x30, (byte) total}, content);
    assertThat(DerUtil.extractAndroidKeyAttestationChallenge(seq)).isEqualTo(challenge);
  }

  @Test
  void extract_android_key_challenge_rejects_sequence_with_fewer_than_5_elements() {
    // SEQUENCE { INTEGER 0 }
    byte[] seq = {0x30, 0x03, 0x02, 0x01, 0x00};
    assertThatThrownBy(() -> DerUtil.extractAndroidKeyAttestationChallenge(seq))
        .isInstanceOf(Fido2VerificationException.class)
        .hasMessageContaining("fewer than 5");
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  private static int[] toIntArray(byte[] bytes) {
    int[] out = new int[bytes.length];
    for (int i = 0; i < bytes.length; i++) out[i] = bytes[i] & 0xff;
    return out;
  }
}
```

- [ ] **Step 2: 테스트 실패 확인 — `DerUtilTest`**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.DerUtilTest"`
Expected: PASS — `DerUtil`이 이미 존재하므로 모두 통과해야 함. 실패하면 `DerUtil` 회귀이므로 즉시 조사.

- [ ] **Step 3: `AttestationTestCerts` 헬퍼 추출**

기존 `AppleAnonymousAttestationVerifierTest` / `AndroidKeyAttestationVerifierTest` / `PackedAttestationVerifierTest`(Phase 3 산출물) + Task 1·2·4의 인라인 `SafetyNetFixture` / `U2fFixture` / `TpmFixture`에서 공통 BouncyCastle 헬퍼를 `AttestationTestCerts`로 추출. 시그니처 골격:

```java
package com.crosscert.passkey.unit.fido2;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;

/** Shared BouncyCastle helpers for attestation verifier tests. */
public final class AttestationTestCerts {

  private AttestationTestCerts() {}

  public static X509Certificate selfSignedCa(String subject, KeyPair caKey) { ... }
  public static X509Certificate leafSignedBy(
      X509Certificate ca, KeyPair caKey, KeyPair leafKey, String subject, List<Extension> extras) { ... }
  public static Extension aaguidExtension(byte[] aaguid) { ... }
  public static Extension tpmEkuExtension() { ... }
  public static Extension tpmSanExtension(String manufacturer, String model, String version) { ... }
  public static byte[] authData(String rpId, int flags, int signCount,
      byte[] aaguid, byte[] credentialId, byte[] coseKey) { ... }
  public static byte[] attestationObjectCbor(String fmt, java.util.Map<String, Object> attStmt, byte[] authData) { ... }
}
```

본문은 기존 Phase 3 테스트(`AppleAnonymousAttestationVerifierTest`·`AndroidKeyAttestationVerifierTest`)의 동일 메서드를 그대로 이동.

- [ ] **Step 4: 기존 verifier 테스트들에서 헬퍼 호출로 교체 + FQN 정리**

대상:
- `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AppleAnonymousAttestationVerifierTest.java`
- `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AndroidKeyAttestationVerifierTest.java`
- `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/PackedAttestationVerifierStrictTest.java`(Phase 3 산출물 — 이름 확인)
- Task 1의 `AndroidSafetyNetAttestationVerifierTest`
- Task 2의 `FidoU2fAttestationVerifierTest`
- Task 4의 `TpmAttestationVerifierTest`

각 파일에서:
1. 인라인 `selfSignedCa`/`leafSignedBy`/`aaguidOfAttestation` 메서드 삭제 → `AttestationTestCerts.*` 호출로 교체
2. `com.crosscert.passkey.fido2.mds.MetadataEntry` 등 FQN을 정식 import로 변경 (Phase 3 인계 사항)

- [ ] **Step 5: `./gradlew check` 전체 실행**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL — 동작 변화 없음, 리팩토링만.

- [ ] **Step 6: 커밋**

```bash
git add server/src/test/java/com/crosscert/passkey/unit/fido2/AttestationTestCerts.java \
        server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/
git commit -m "test(fido2): AttestationTestCerts 공용 헬퍼 추출 + DerUtilTest 추가 + FQN 정리"
```

---

## Task 6: `RegistrationVerificationRequest`·`RegistrationVerifier` strict 와이어링

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerificationRequest.java`
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerifier.java:80`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationVerifierStrictTest.java` (신규)

- [ ] **Step 1: 실패 테스트 작성**

```java
package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import java.util.List;
import org.junit.jupiter.api.Test;

class RegistrationVerifierStrictTest {

  @Test
  void passes_non_strict_when_trust_anchors_null() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(), reg.clientDataJson(), reg.challenge(),
            List.of("https://example.com"), "example.com", false, /*trustAnchors*/ null);

    RegistrationVerificationResult result = new RegistrationVerifier().verify(req);

    assertThat(result.format()).isEqualTo("packed");
  }

  @Test
  void rejects_strict_when_aaguid_not_in_mds() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    MdsTrustAnchorSource emptySource = new MdsTrustAnchorSource(List.of());

    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(), reg.clientDataJson(), reg.challenge(),
            List.of("https://example.com"), "example.com", false, emptySource);

    assertThatThrownBy(() -> new RegistrationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isIn(FailureReason.MDS_TRUST_FAILED, FailureReason.TRUST_PATH_INVALID);
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.RegistrationVerifierStrictTest"`
Expected: FAIL — `RegistrationVerificationRequest`의 생성자에 7번째 인자가 없음.

- [ ] **Step 3: `RegistrationVerificationRequest`에 필드 추가**

`RegistrationVerificationRequest.java`:

```java
package com.crosscert.passkey.fido2;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import java.util.List;

/**
 * Inputs for verifying a {@code navigator.credentials.create()} registration. {@code
 * attestationObject} and {@code clientDataJson} are the raw (base64url-decoded) ceremony outputs;
 * {@code expectedChallenge} is the raw challenge the server issued. {@code trustAnchors} is the MDS
 * trust anchor source for strict registration; null means non-strict (no cert chain validation,
 * no revocation check).
 */
public record RegistrationVerificationRequest(
    byte[] attestationObject,
    byte[] clientDataJson,
    byte[] expectedChallenge,
    List<String> expectedOrigins,
    String expectedRpId,
    boolean userVerificationRequired,
    MdsTrustAnchorSource trustAnchors) {}
```

- [ ] **Step 4: `RegistrationVerifier`가 `req.trustAnchors()` 전달**

`RegistrationVerifier.java:78-81` (verify 메서드의 attestation 호출):

```java
    AttestationResult attestation =
        AttestationVerifiers.forFormat(attestationObject.format())
            .verify(attestationObject, clientDataHash, req.trustAnchors());
```

(`null` 하드코드 → `req.trustAnchors()`로 변경)

- [ ] **Step 5: 기존 호출처 수정 — 컴파일 에러 해소**

`RegistrationVerificationRequest`를 직접 생성하는 모든 호출처 찾기:

Run: `grep -rn "new RegistrationVerificationRequest" server/src/`
Expected: `RegistrationService.verifyWithCore`, 기존 verifier 테스트들.

각 호출처에 마지막 인자 `null` 추가. `RegistrationService.verifyWithCore` 부분:

```java
    RegistrationVerificationRequest verifyReq =
        new RegistrationVerificationRequest(
            Base64UrlCodec.decode(req.attestationObjectB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(stored.challengeB64u()),
            cfg.originList(),
            cfg.getRpId(),
            cfg.getUserVerification().isStrictRequired(),
            null); // Task 7에서 trustAnchorSource로 교체
```

- [ ] **Step 6: 테스트 통과 확인 + `./gradlew check`**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.fido2.RegistrationVerifierStrictTest"`
Expected: PASS — 2 tests.

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 7: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerificationRequest.java \
        server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerifier.java \
        server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java \
        server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationVerifierStrictTest.java
git commit -m "feat(fido2): RegistrationVerificationRequest.trustAnchors 필드 + RegistrationVerifier 전달"
```

---

## Task 7: `RegistrationService`를 strict까지 단일화 — `verifyWithWebauthn4j` 삭제

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java`
- Test: 기존 `server/src/test/java/com/crosscert/passkey/unit/credential/RegistrationServiceTest.java`

이 task는 import는 아직 webauthn4j를 쓰지만 **strict 분기를 자체 코어로 단일화**한다. `webauthn4j-core` 의존성과 import 제거는 Task 10에서 한다. 이 task는 분기 로직만 바꾼다.

- [ ] **Step 1: 기존 단위 테스트가 그대로 통과해야 함을 확인**

Run: `./gradlew test --tests "com.crosscert.passkey.unit.credential.RegistrationServiceTest"`
Expected: PASS (baseline 확인).

- [ ] **Step 2: `RegistrationService` 분기 로직 단일화**

`RegistrationService.java`의 `finishRegistration`에서 `if (policy.isMdsStrict())` 블록 + `verifyWithWebauthn4j` 호출 + `AttestationFacts` private record를 모두 제거. `verifyWithCore`가 strict까지 처리하도록 시그니처 확장:

```java
import com.crosscert.passkey.credential.metadata.MdsConfig.MdsTrustAnchorSourceHolder;
import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
// (webauthn4j import는 Task 10에서 제거)

// 필드 추가:
private final ObjectProvider<MdsTrustAnchorSourceHolder> mdsHolderProvider;

// 생성자 인자 추가:
public RegistrationService(
    ...,
    ObjectProvider<MdsTrustAnchorSourceHolder> mdsHolderProvider,
    ...) {
  ...
  this.mdsHolderProvider = mdsHolderProvider;
  ...
}
```

`finishRegistration`의 분기 부분(현 230-242행)을 다음으로 교체:

```java
    MdsTrustAnchorSource trustAnchors = null;
    if (policy.isMdsStrict()) {
      MdsTrustAnchorSourceHolder holder = mdsHolderProvider.getIfAvailable();
      MdsTrustAnchorSource current = holder == null ? null : holder.current();
      if (current == null) {
        log.error(
            "register.mds.unavailable tenantId={} tenantUserId={} — "
                + "tenant requires mdsStrict but MDS BLOB is not loaded",
            cfg.getTenantId(),
            stored.tenantUserId());
        metrics.getRegistrationFailure().increment();
        throw new BusinessException(ErrorCode.MDS_UNAVAILABLE);
      }
      log.info(
          "register.mds.strict.engaged tenantId={} tenantUserId={}",
          cfg.getTenantId(),
          stored.tenantUserId());
      trustAnchors = current;
    }
    RegistrationVerificationResult result = verifyWithCore(cfg, stored, req, trustAnchors);

    UUID aaguid = bytesToUuid(result.aaguid());
    long signatureCounter = result.signCount();
    boolean backupEligible = result.backupEligible();
    boolean backupState = result.backupState();
    // ... 정책 판단·credential 저장은 그대로
```

`verifyWithCore` 시그니처와 본문:

```java
  private RegistrationVerificationResult verifyWithCore(
      TenantWebauthnConfig cfg,
      ChallengeRecord stored,
      RegistrationVerifyRequest req,
      MdsTrustAnchorSource trustAnchors) {
    RegistrationVerificationRequest verifyReq =
        new RegistrationVerificationRequest(
            Base64UrlCodec.decode(req.attestationObjectB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(stored.challengeB64u()),
            cfg.originList(),
            cfg.getRpId(),
            cfg.getUserVerification().isStrictRequired(),
            trustAnchors);
    try {
      return new RegistrationVerifier().verify(verifyReq);
    } catch (Fido2VerificationException e) {
      mapAndThrow(cfg, stored, e);
      throw new IllegalStateException("unreachable");
    }
  }

  /** Map fido2 core failure reasons to {@code ErrorCode} and throw — strict/non-strict unified. */
  private void mapAndThrow(TenantWebauthnConfig cfg, ChallengeRecord stored, Fido2VerificationException e) {
    metrics.getRegistrationFailure().increment();
    switch (e.reason()) {
      case MDS_TRUST_FAILED -> {
        log.warn(
            "register.mds.trust_failed tenantId={} tenantUserId={} detail={}",
            cfg.getTenantId(), stored.tenantUserId(), e.getMessage());
        auditService.append(
            com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
            com.crosscert.passkey.audit.domain.ActorType.END_USER,
            stored.tenantUserId().toString(),
            "AUTHENTICATOR", "trust_anchor_missing",
            java.util.Map.of("reason", e.getMessage()));
        throw new BusinessException(ErrorCode.MDS_TRUST_FAILED, e.getMessage());
      }
      case AUTHENTICATOR_REVOKED -> {
        log.error(
            "register.authenticator.revoked tenantId={} tenantUserId={} detail={}",
            cfg.getTenantId(), stored.tenantUserId(), e.getMessage());
        auditService.append(
            com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
            com.crosscert.passkey.audit.domain.ActorType.END_USER,
            stored.tenantUserId().toString(),
            "AUTHENTICATOR", "revoked",
            java.util.Map.of("reason", e.getMessage()));
        throw new BusinessException(ErrorCode.AUTHENTICATOR_REVOKED, e.getMessage());
      }
      case TRUST_PATH_INVALID -> {
        log.warn(
            "register.mds.trust_failed tenantId={} tenantUserId={} detail={}",
            cfg.getTenantId(), stored.tenantUserId(), e.getMessage());
        throw new BusinessException(ErrorCode.MDS_TRUST_FAILED, e.getMessage());
      }
      default -> {
        log.warn(
            "register.attestation.invalid tenantId={} tenantUserId={} reason={} detail={}",
            cfg.getTenantId(), stored.tenantUserId(), e.reason(), e.getMessage());
        throw new BusinessException(ErrorCode.ATTESTATION_INVALID, e.getMessage());
      }
    }
  }
```

`AttestationFacts` private record + `verifyWithWebauthn4j` 메서드 + `bytesToUuid` 위에 있던 webauthn4j ObjectConverter/AttestedCredentialDataConverter 필드 + `strictManagerProvider` 필드 + 관련 생성자 인자 모두 **삭제**.

신규로 사용된 `RegistrationVerificationResult` 메서드: `aaguid()`(byte[]) / `signCount()` / `backupEligible()` / `backupState()` / `attestedCredentialData()` / `credentialId()` — 이미 Milestone A에서 정의돼 있음. `Credential.create` 호출의 `facts.credentialIdB64u()`는 `Base64UrlCodec.encode(result.credentialId())`로, `facts.attestedCredentialData()`는 `result.attestedCredentialData()`로 교체.

- [ ] **Step 3: 단위 테스트가 그대로 통과**

`RegistrationServiceTest`는 fail-closed 분기 위주로 짜여 있어 (MDS_UNAVAILABLE / CHALLENGE_NOT_FOUND / AAGUID_NOT_ALLOWED 등), 분기 로직만 바꿔도 통과해야 한다. MDS_UNAVAILABLE 분기는 이제 `mdsHolderProvider.getIfAvailable() == null || holder.current() == null`로 변경됐으므로, 그 테스트가 `strictManagerProvider`를 mock하던 부분을 `mdsHolderProvider`로 교체.

Run: `./gradlew test --tests "com.crosscert.passkey.unit.credential.RegistrationServiceTest"`
Expected: PASS.

- [ ] **Step 4: `./gradlew check` 전체 실행**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java \
        server/src/test/java/com/crosscert/passkey/unit/credential/RegistrationServiceTest.java
git commit -m "feat(fido2): RegistrationService strict 경로 자체 코어로 단일화 — verifyWithWebauthn4j 삭제"
```

---

## Task 8: strict 경로 통합 테스트 + MDS BLOB fixture

**Files:**
- Create: `server/src/test/resources/fido2/mds-blob-fixture-root.cer`
- Create: `server/src/test/resources/fido2/mds-blob-fixture.jws`
- Create: `server/src/test/java/com/crosscert/passkey/integration/credential/MdsBlobFixtureBuilder.java` (helper — generates the two files above on demand)
- Create: `server/src/test/java/com/crosscert/passkey/integration/credential/RegistrationStrictIntegrationTest.java`
- Modify: `server/src/test/java/com/crosscert/passkey/integration/support/AdminEnabledIntegrationTestBase.java` (재사용 가능하면) 또는 신규 `MdsEnabledIntegrationTestBase`

`MdsBlobFixtureBuilder`는 6개 fmt를 위한 AAGUID 7개(packed/apple/android-key/android-safetynet/fido-u2f/tpm/revoked) entry를 담은 MDS3 BLOB JWS를 BouncyCastle로 생성. 빌더는 `@BeforeAll`에서 `src/test/resources/fido2/mds-blob-fixture.jws` 파일이 없으면 생성하고, 있으면 그대로 사용 — 결정론.

- [ ] **Step 1: `MdsBlobFixtureBuilder` 작성**

```java
package com.crosscert.passkey.integration.credential;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

/** Builds a deterministic MDS3 BLOB JWS for integration tests. */
final class MdsBlobFixtureBuilder {

  static final UUID PACKED_AAGUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
  static final UUID APPLE_AAGUID  = UUID.fromString("22222222-2222-2222-2222-222222222222");
  static final UUID ANDROID_KEY_AAGUID = UUID.fromString("33333333-3333-3333-3333-333333333333");
  static final UUID SAFETYNET_AAGUID   = UUID.fromString("44444444-4444-4444-4444-444444444444");
  static final UUID U2F_AAGUID         = UUID.fromString("55555555-5555-5555-5555-555555555555");
  static final UUID TPM_AAGUID         = UUID.fromString("66666666-6666-6666-6666-666666666666");
  static final UUID REVOKED_AAGUID     = UUID.fromString("77777777-7777-7777-7777-777777777777");

  /** Generate {@code mds-blob-fixture.jws} and {@code mds-blob-fixture-root.cer} if missing. */
  static void ensureBuilt(Path testResourcesFido2Dir) throws Exception {
    Path jwsPath = testResourcesFido2Dir.resolve("mds-blob-fixture.jws");
    Path rootPath = testResourcesFido2Dir.resolve("mds-blob-fixture-root.cer");
    if (Files.exists(jwsPath) && Files.exists(rootPath)) {
      return;
    }
    // 1. BouncyCastle: generate root CA RSA 2048, sign leaf "MDS BLOB signer".
    // 2. Build per-AAGUID attestation root cert (one per fmt above) — these are the MDS trust anchors.
    // 3. Compose payload JSON: { legalHeader, no, nextUpdate, entries: [ {aaguid, attestationRootCertificates, statusReports} ] }
    // 4. nimbus JWSObject: header alg=RS256, x5c=[leaf, root], payload=base64url(json). Sign with leaf private key.
    // 5. Write jwsPath (compact JWS string) and rootPath (root cert DER).
    ...
  }
}
```

본문은 Phase 3 `MdsTestFixtures` (이미 `server/src/test/java/com/crosscert/passkey/unit/fido2/mds/`에 존재) 참고하여 BouncyCastle CA·leaf 생성 + nimbus JWS 패턴 재사용.

- [ ] **Step 2: `RegistrationStrictIntegrationTest` 작성**

```java
package com.crosscert.passkey.integration.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.credential.api.RegistrationVerifyRequest;
import com.crosscert.passkey.credential.service.RegistrationService;
import com.crosscert.passkey.integration.support.IntegrationTestBase;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * End-to-end strict registration tests over the self-implemented FIDO2 core + Oracle DB + a fixed
 * MDS BLOB fixture. Covers all 7 attestation formats (none + 6 trust-anchored) with happy-path and
 * reject scenarios.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RegistrationStrictIntegrationTest extends IntegrationTestBase {

  @DynamicPropertySource
  static void mdsProps(DynamicPropertyRegistry r) {
    Path fixtureRoot = Paths.get("src/test/resources/fido2/mds-blob-fixture-root.cer").toAbsolutePath();
    Path fixtureBlob = Paths.get("src/test/resources/fido2/mds-blob-fixture.jws").toAbsolutePath();
    r.add("passkey.mds.enabled", () -> "true");
    r.add("passkey.mds.blob-url", () -> fixtureBlob.toUri().toString());
    r.add("passkey.mds.root-certificate-path", () -> "file:" + fixtureRoot);
    r.add("passkey.mds.refresh-cron", () -> "-"); // Disable scheduler in tests.
  }

  @BeforeAll
  void buildFixtures() throws Exception {
    MdsBlobFixtureBuilder.ensureBuilt(Paths.get("src/test/resources/fido2"));
  }

  @Autowired RegistrationService registrationService;
  // + tenant seed helpers from IntegrationTestBase / TenantSeed.

  @Test
  void none_format_passes_in_strict_tenant() { ... }

  @Test
  void packed_full_passes_with_matching_trust_anchor() { ... }

  @Test
  void packed_full_rejected_when_aaguid_not_in_mds() { ... }

  @Test
  void apple_passes_with_matching_trust_anchor() { ... }

  @Test
  void apple_rejected_when_aaguid_revoked() { ... }

  @Test
  void android_key_passes_with_matching_trust_anchor() { ... }

  @Test
  void android_key_rejected_when_chain_does_not_validate() { ... }

  @Test
  void android_safetynet_passes_with_matching_trust_anchor() { ... }

  @Test
  void android_safetynet_rejected_when_aaguid_not_in_mds() { ... }

  @Test
  void fido_u2f_passes_with_matching_trust_anchor() { ... }

  @Test
  void fido_u2f_rejected_when_chain_does_not_validate() { ... }

  @Test
  void tpm_passes_with_matching_trust_anchor() { ... }

  @Test
  void tpm_rejected_when_aaguid_revoked() { ... }
}
```

각 happy-path 메서드는: (a) MDS-등록 AAGUID로 BouncyCastle attestation 생성 → `MdsBlobFixtureBuilder`의 해당 AAGUID의 leaf cert로 서명 → `MdsTrustAnchorSource`가 이 cert를 신뢰. (b) `mdsStrict=true` 테넌트 시드. (c) `registrationService.beginRegistration(...)` → challenge 받기. (d) `registrationService.finishRegistration(verifyRequest)` → 성공. 각 reject 메서드는 같은 흐름이지만 `assertThatThrownBy(...)` + `ErrorCode` 단언.

- [ ] **Step 3: `./gradlew check` 전체 실행 (integration 포함)**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. 13 strict integration tests 통과. Oracle 시작 필요 — `docker compose up -d`.

- [ ] **Step 4: 커밋**

```bash
git add server/src/test/resources/fido2/ \
        server/src/test/java/com/crosscert/passkey/integration/credential/
git commit -m "test(fido2): strict 등록 통합 테스트 + MDS BLOB fixture (6 fmt × happy+reject)"
```

---

## Task 9: 차등 테스트 → 골든 벡터 전환

**Files:**
- Create: `server/src/test/resources/fido2/golden/registration-w3c-l3-example.cbor`
- Create: `server/src/test/resources/fido2/golden/authentication-w3c-l3-example.cbor`
- Create: `server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationGoldenVectorTest.java`
- Create: `server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionGoldenVectorTest.java`
- Modify: `server/src/test/java/com/crosscert/passkey/unit/fido2/Fido2Fixtures.java` (webauthn4j import 삭제 — 이미 attestationObject 빌더가 자체 구현이므로 제거 후 통과해야 함)
- Delete: `server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationDifferentialTest.java`
- Delete: `server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionDifferentialTest.java`

`Fido2Fixtures`는 현재 webauthn4j를 직접 import하지 않으면 그대로 둘 수 있다. 위 Read 결과 보면 `Fido2Fixtures.java`는 BouncyCastle/JCA만 쓰고 있어 그대로 유지 가능 — webauthn4j import 정리만 확인.

- [ ] **Step 1: W3C 명세 예제 골든 벡터 fixture 추가**

`docs/superpowers/specs/2026-05-23-fido2-core-milestone-b-design.md` §11.3에 명시된대로 W3C WebAuthn L2·L3 명세의 attestationObject / assertion 예제를 사용. W3C 예제는 spec 문서에 hex로 명시돼 있다 ([WebAuthn L3 §6.5 example](https://www.w3.org/TR/webauthn-3/), `none` attestation 예제). 두 파일을 생성:

- `registration-w3c-l3-example.cbor`: W3C 명세의 `none` attestationObject 예제 (raw bytes)
- `authentication-w3c-l3-example.cbor`: 같은 명세의 assertion 예제

별도 `golden-spec.md`(같은 디렉터리)에 출처·challenge·expected fields 명시.

- [ ] **Step 2: `RegistrationGoldenVectorTest` 작성**

```java
package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;

class RegistrationGoldenVectorTest {

  @Test
  void w3c_l3_none_example_verifies() throws Exception {
    byte[] attestationObject =
        Files.readAllBytes(Paths.get("src/test/resources/fido2/golden/registration-w3c-l3-example.cbor"));
    byte[] clientDataJson = /* W3C example clientDataJSON literal */;
    byte[] expectedChallenge = /* base64url-decoded challenge from the same example */;

    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            attestationObject, clientDataJson, expectedChallenge,
            List.of("https://example.com"), "example.com", false, null);

    RegistrationVerificationResult result = new RegistrationVerifier().verify(req);

    assertThat(result.format()).isEqualTo("none");
    assertThat(result.credentialId()).hasSizeBetween(1, 1023);
  }

  // For self-built fixtures (each fmt), reuse Fido2Fixtures and AttestationTestCerts.
  @Test
  void self_built_packed_attestation_verifies() throws Exception {
    Fido2Fixtures.Registration reg = Fido2Fixtures.validRegistration("packed", "https://example.com", "example.com");
    RegistrationVerificationRequest req =
        new RegistrationVerificationRequest(
            reg.attestationObject(), reg.clientDataJson(), reg.challenge(),
            List.of("https://example.com"), "example.com", false, null);

    RegistrationVerificationResult result = new RegistrationVerifier().verify(req);

    assertThat(result.format()).isEqualTo("packed");
  }

  // Repeat for each of: apple, android-key, android-safetynet, fido-u2f, tpm — using
  // AttestationTestCerts to generate the fixture and asserting the verifier returns the expected
  // format + credential metadata.

  // ... 5 more tests ...
}
```

`AssertionGoldenVectorTest`도 동일 패턴(`AuthenticationVerifier`로 검증).

- [ ] **Step 3: 차등 테스트 삭제**

```bash
rm server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationDifferentialTest.java
rm server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionDifferentialTest.java
```

- [ ] **Step 4: `Fido2Fixtures`에서 webauthn4j 의존 잔존 점검**

Run: `grep -n "webauthn4j" server/src/test/java/com/crosscert/passkey/unit/fido2/Fido2Fixtures.java`
Expected: 0건. 있다면 삭제 (이 파일은 자체 attestationObject 생성기이므로 webauthn4j 없이 동작해야 함).

- [ ] **Step 5: `./gradlew check` 전체 실행**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. 차등 테스트 자리에 골든 벡터 테스트가 들어섰고, 안전망이 끊기지 않음.

- [ ] **Step 6: 커밋**

```bash
git add server/src/test/resources/fido2/golden/ \
        server/src/test/java/com/crosscert/passkey/unit/fido2/*GoldenVectorTest.java \
        server/src/test/java/com/crosscert/passkey/unit/fido2/Fido2Fixtures.java
git rm server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationDifferentialTest.java \
       server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionDifferentialTest.java
git commit -m "test(fido2): 차등 테스트 → 골든 벡터 기반 전환 (W3C L3 예제 + 자체 빌드)"
```

---

## Task 10: webauthn4j import 단계적 제거 (production 코드)

각 substep 끝에서 `./gradlew check` 통과 필수.

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java` (10a)
- Delete: `server/src/main/java/com/crosscert/passkey/credential/webauthn/WebAuthnConfig.java` (10b)
- Delete: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsTrustAnchorRepositoryConfig.java` (10b)
- Modify: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobProvider.java` (10c)
- Modify: `server/src/main/java/com/crosscert/passkey/credential/metadata/MdsDiagController.java` (10d)

- [ ] **Step 10a: `RegistrationService`에서 webauthn4j import 제거**

`RegistrationService.java` 상단의 다음 import 모두 삭제:
- `com.webauthn4j.WebAuthnManager`
- `com.webauthn4j.converter.AttestedCredentialDataConverter`
- `com.webauthn4j.converter.exception.DataConversionException`
- `com.webauthn4j.converter.util.ObjectConverter`
- `com.webauthn4j.data.RegistrationData`
- `com.webauthn4j.data.RegistrationParameters`
- `com.webauthn4j.data.attestation.authenticator.AAGUID`
- `com.webauthn4j.data.attestation.authenticator.AttestedCredentialData`
- `com.webauthn4j.data.client.Origin`
- `com.webauthn4j.data.client.challenge.DefaultChallenge`
- `com.webauthn4j.metadata.exception.BadStatusException`
- `com.webauthn4j.server.ServerProperty`
- `com.webauthn4j.verifier.exception.TrustAnchorNotFoundException`
- `com.webauthn4j.verifier.exception.VerificationException`

Task 7에서 `verifyWithWebauthn4j` 메서드가 이미 삭제됐으니 이 import들은 모두 unused 상태일 것. 컴파일러가 보고할 수 있게 IDE auto-import 끄고 수동 정리.

`strictManagerProvider`/`nonStrictManager`/`objectConverter`/`attestedConverter` 필드 + 생성자 인자도 모두 제거.

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 10a 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java
git commit -m "refactor(fido2): RegistrationService에서 webauthn4j import 완전 제거"
```

- [ ] **Step 10b: `WebAuthnConfig`·`MdsTrustAnchorRepositoryConfig` 삭제**

```bash
rm server/src/main/java/com/crosscert/passkey/credential/webauthn/WebAuthnConfig.java
rm server/src/main/java/com/crosscert/passkey/credential/metadata/MdsTrustAnchorRepositoryConfig.java
```

이 두 빈을 참조하는 곳이 있는지 확인:

Run: `grep -rn "WebAuthnConfig\|MdsTrustAnchorRepositoryConfig\|TrustAnchorRepository\|nonStrictWebAuthnManager\|strictWebAuthnManager" server/src/`
Expected: 0건 (Task 10a 후 RegistrationService도 이미 정리).

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. Spring context가 webauthn4j 빈 없이 떠야 함 — 통합 테스트가 회귀 감지기.

- [ ] **Step 10b 커밋**

```bash
git rm server/src/main/java/com/crosscert/passkey/credential/webauthn/WebAuthnConfig.java \
       server/src/main/java/com/crosscert/passkey/credential/metadata/MdsTrustAnchorRepositoryConfig.java
git commit -m "refactor(fido2): WebAuthnConfig·MdsTrustAnchorRepositoryConfig 삭제"
```

- [ ] **Step 10c: `MdsBlobProvider` 정리**

`MdsBlobProvider.java`에서:
- `implements MetadataBLOBProvider` 제거
- `delegate: FidoMDS3MetadataBLOBProvider` 필드 + 생성자에서의 초기화 제거
- `provide()` 메서드 삭제 (자체 `currentTrustAnchorSource()`만 노출)
- `lastBlob: AtomicReference<MetadataBLOB>` 필드 → `lastInhouseBlob: AtomicReference<MetadataBlob>` (자체 모델)
- `refresh()` 메서드에서 `delegate.refresh()` / `delegate.provide()` / 디버그 로깅의 `MetadataBLOBPayloadEntry` 사용 제거. 자체 `refreshInHouse()`를 직접 inline해서 `refresh()` 하나로 통합.
- 모든 `com.webauthn4j` import 제거

수정 후 클래스 구조:

```java
@Slf4j
@Component
@ConditionalOnProperty(prefix = "passkey.mds", name = "enabled", havingValue = "true")
public class MdsBlobProvider {

  private final MdsProperties props;
  private final X509Certificate rootCa;
  private final RestClient restClient;
  private final AtomicReference<MdsTrustAnchorSource> trustAnchorSource = new AtomicReference<>();
  @Getter private final AtomicReference<Instant> lastFetched = new AtomicReference<>();
  @Getter private final AtomicReference<MetadataBlob> lastBlob = new AtomicReference<>();

  @Autowired
  public MdsBlobProvider(MdsProperties props, ResourceLoader resourceLoader) {
    this.props = props;
    this.rootCa = loadRootCa(resourceLoader);
    this.restClient = RestClient.create();
    log.info("mds.provider.constructed url={} rootCaSubject={}",
        props.getBlobUrl(), rootCa.getSubjectX500Principal().getName());
  }

  @PostConstruct
  void warmUp() { ... try refresh, log on failure ... }

  public synchronized void refresh() {
    String jws = restClient.get().uri(props.getBlobUrl()).retrieve().body(String.class);
    MetadataBlob blob = MetadataBlob.parse(jws, rootCa);
    trustAnchorSource.set(new MdsTrustAnchorSource(blob.entries()));
    lastBlob.set(blob);
    lastFetched.set(Instant.now());
    log.info("mds.refresh.success entries={} nextUpdate={}", blob.entries().size(), blob.nextUpdate());
  }

  public MdsTrustAnchorSource currentTrustAnchorSource() { return trustAnchorSource.get(); }

  private X509Certificate loadRootCa(ResourceLoader resourceLoader) { ... unchanged ... }
}
```

`MdsBlobProvider`의 `provide()`를 호출하던 곳이 있는지 확인:

Run: `grep -rn "blobProvider.provide()\|MetadataBLOBProvider" server/src/`
Expected: `MdsDiagController`만(다음 substep에서 처리).

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. `MdsDiagController`가 webauthn4j `MetadataBLOB` 타입을 직접 쓰던 부분이 컴파일 에러 → 다음 substep으로.

> **주의:** 컴파일 에러 발생 시 그대로 Step 10d로. Step 10c 단독 커밋은 하지 않음 (10c+10d 묶음 커밋).

- [ ] **Step 10d: `MdsDiagController` webauthn4j 타입 제거**

`MdsDiagController.java`에서:
- `import com.webauthn4j.metadata.data.MetadataBLOB;` 제거
- `ObjectProvider<MdsBlobProvider>`는 유지 (자체 클래스)
- `buildStatusPayload`의 `MetadataBLOB blob` 변수 → `MetadataBlob blob = provider.getLastBlob().get()`
- `blob.getPayload().getEntries().size()` → `blob.entries().size()`
- `blob.getPayload().getNextUpdate()` → `blob.nextUpdate()`
- `blob.getPayload().getNo()` → `MetadataBlob`에 serialNumber 필드가 있는지 확인 — 없다면 추가하거나 status payload에서 항목 제거 (Phase 3 `MetadataBlob` 구조 점검 필요)

`MetadataBlob`의 현재 필드를 확인:

Run: `grep -n "public record MetadataBlob\|public List<MetadataEntry> entries\|nextUpdate\|serialNumber" server/src/main/java/com/crosscert/passkey/fido2/mds/MetadataBlob.java`

`serialNumber`/`no`가 없다면 `MetadataBlob` record에 필드 추가 + `parse()`에서 JSON `no` 필드 읽기.

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL. 이제 production에 `com.webauthn4j` import 0건.

검증:

Run: `grep -r "com.webauthn4j" server/src/main/ | grep -v "// "`
Expected: 0건.

- [ ] **Step 10c+10d 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/credential/metadata/MdsBlobProvider.java \
        server/src/main/java/com/crosscert/passkey/credential/metadata/MdsDiagController.java \
        server/src/main/java/com/crosscert/passkey/fido2/mds/MetadataBlob.java
git commit -m "refactor(fido2): MdsBlobProvider/MdsDiagController에서 webauthn4j 타입 완전 제거"
```

---

## Task 11: `build.gradle.kts`에서 webauthn4j 의존성 삭제 + ArchUnit 가드

**Files:**
- Modify: `server/build.gradle.kts:57-63`
- Modify: `server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java` (Rule 7 주석 갱신 + 신규 가드 Rule 추가)

- [ ] **Step 1: webauthn4j 의존성 삭제**

`server/build.gradle.kts`의 다음 라인 + 위/아래 주석 블록 삭제:

```kotlin
// webauthn4j — M2 BE-005
implementation("com.webauthn4j:webauthn4j-core:0.27.0.RELEASE")

// FIDO MDS3 BLOB parsing + trust anchor sourcing. ...
implementation("com.webauthn4j:webauthn4j-metadata:0.27.0.RELEASE")
```

라인 96 부근의 BouncyCastle 주석에서 "webauthn4j-metadata does not pull BouncyCastle in transitively" 문구는 webauthn4j 제거됐으니 단순화 가능 — "BouncyCastle is not on the production classpath" 정도로 갱신.

- [ ] **Step 2: 신규 ArchUnit Rule 추가 — webauthn4j import 금지 가드**

`PackageArchitectureTest.java`에 Rule 8 추가:

```java
  // Rule 8: production code (everything under ROOT) must not import anything from com.webauthn4j —
  // Milestone B Phase 4 removed the dependency entirely. The fido2 core was already forbidden by
  // Rule 7; this rule extends the ban to credential/admin/etc. domain code, guarding against
  // accidental re-introduction via a future merge that resurrects the dependency.
  @Test
  void no_production_code_depends_on_webauthn4j() {
    noClasses()
        .that()
        .resideInAPackage(ROOT + "..")
        .should()
        .dependOnClassesThat()
        .resideInAnyPackage("com.webauthn4j..")
        .check(CLASSES);
  }
```

Rule 7 주석을 갱신:

```java
  // Rule 7: the fido2 core is a pure WebAuthn implementation — it must not depend on any domain
  // package, on Spring, or on the application's exception types. Only java.*/javax.* (JCA, LDAP
  // name parsing) + the fido2 package itself + Jackson (clientDataJSON parsing) + nimbus-jose-jwt
  // (MDS3 BLOB JWS verification + android-safetynet JWS verification) + the test-only BouncyCastle
  // attestation-cert builder are permitted. Milestone B Phase 4 removed webauthn4j entirely from
  // production (see Rule 8); fido2 was already forbidden it.
```

- [ ] **Step 3: `./gradlew check` + transitive 의존성 확인**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

Run: `./gradlew dependencies --configuration runtimeClasspath | grep -i webauthn4j || echo "OK: no webauthn4j on runtime classpath"`
Expected: `OK: no webauthn4j on runtime classpath`.

Run: `./gradlew dependencies --configuration testRuntimeClasspath | grep -i webauthn4j || echo "OK: no webauthn4j on test classpath"`
Expected: `OK: no webauthn4j on test classpath`.

- [ ] **Step 4: 커밋**

```bash
git add server/build.gradle.kts \
        server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java
git commit -m "refactor(fido2): webauthn4j 의존성 완전 제거 + ArchUnit Rule 8 가드"
```

---

## Task 12: 마무리 — `FailureReason.UNSUPPORTED_ALGORITHM` 정리 + `architecture.md` 갱신

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java`
- Modify: `docs/architecture.md` §1 (Tech Stack에서 webauthn4j 제거) + §11 (변경 이력 추가)

- [ ] **Step 1: `UNSUPPORTED_ALGORITHM` 사용처 확인**

Run: `grep -rn "UNSUPPORTED_ALGORITHM" server/src/`
Expected:
- `TpmAttestationVerifier` (`jcaAlgorithmForCoseAlg`) — Task 4에서 사용처 생김
- `Fido2VerificationException` enum 정의

사용처가 있으므로 enum 유지. 추가로 다른 verifier들도 `UNSUPPORTED_ALGORITHM`을 쓸 수 있는지 점검 — 예: `AndroidKeyAttestationVerifier`의 `jcaAlgorithmForCoseAlg`가 unknown alg에 대해 `ATTESTATION_INVALID`를 throw하는데, 의미적으로는 `UNSUPPORTED_ALGORITHM`이 더 정확함. 일관성을 위해 `AndroidKeyAttestationVerifier`/`PackedAttestationVerifier`/`AppleAnonymousAttestationVerifier`의 unknown-alg 경로도 `UNSUPPORTED_ALGORITHM`으로 통일:

Run: `grep -n "unsupported alg\|UNSUPPORTED_ALGORITHM\|ATTESTATION_INVALID.*alg" server/src/main/java/com/crosscert/passkey/fido2/attestation/*.java`

각 verifier의 unknown-alg throw 사이트를 `FailureReason.UNSUPPORTED_ALGORITHM`으로 통일.

- [ ] **Step 2: 영향 받은 verifier 테스트 보정**

unknown-alg 케이스를 테스트하던 verifier 테스트의 expected reason을 `UNSUPPORTED_ALGORITHM`으로 변경.

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: `docs/architecture.md` 갱신**

`docs/architecture.md` §1 Tech Stack 섹션에서 `webauthn4j 0.27.0.RELEASE` 라인 제거. §11 변경 이력에 추가:

```markdown
- 2026-05-23: FIDO2 코어 Milestone B Phase 4 완료 — webauthn4j 완전 제거. attestation 6포맷 + strict/non-strict 단일 경로 모두 자체 코어(`com.crosscert.passkey.fido2`) 단독으로 동작. `WebAuthnConfig`·`MdsTrustAnchorRepositoryConfig` 삭제, `MdsBlobProvider` 자체 모델 단독화, ArchUnit Rule 8(production에서 webauthn4j import 금지) 추가. 차등 테스트 → W3C L3 명세 예제 + 자체 빌드 골든 벡터 기반 전환.
```

- [ ] **Step 4: 최종 `./gradlew check`**

Run: `./gradlew check`
Expected: BUILD SUCCESSFUL — Milestone B Phase 4 클로즈.

- [ ] **Step 5: 커밋**

```bash
git add server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java \
        server/src/main/java/com/crosscert/passkey/fido2/attestation/ \
        server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/ \
        docs/architecture.md
git commit -m "docs(fido2): Milestone B Phase 4 마무리 — UNSUPPORTED_ALGORITHM 일관화 + architecture.md §11 갱신"
```

---

## 완료 조건 점검 체크리스트

Phase 4 종료 시점에 다음을 모두 만족해야 한다:

- [ ] `grep -r "com.webauthn4j" server/src/main/` → 0건
- [ ] `./gradlew dependencies --configuration runtimeClasspath | grep webauthn4j` → 0건
- [ ] `AttestationVerifiers` 레지스트리에 7 fmt 등록 (none / packed / apple / android-key / android-safetynet / fido-u2f / tpm)
- [ ] `RegistrationService`에 `verifyWithWebauthn4j` / `AttestationFacts` 미존재
- [ ] strict 통합 테스트 13건 (`RegistrationStrictIntegrationTest`) 통과
- [ ] 차등 테스트 0건, 골든 벡터 테스트 ≥ 7건 (`RegistrationGoldenVectorTest` + `AssertionGoldenVectorTest`)
- [ ] ArchUnit Rule 7·8 통과
- [ ] `./gradlew check` 전체 BUILD SUCCESSFUL
- [ ] `docs/architecture.md` §1·§11 갱신 반영

Phase 4 후 cross-origin 정책 적용은 **별도 작업**(Milestone C 또는 backlog). `crossOrigin` 값은 이미 `RegistrationVerificationResult`/`AuthenticationVerificationResult`에 노출됨 (Milestone A 인계 사항) — 호출자(`RegistrationService`)에서 정책 거부 결정만 추가하면 된다.
