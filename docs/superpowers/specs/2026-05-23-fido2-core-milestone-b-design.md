# FIDO2 코어 자체 구현 — Milestone B 설계

- 작성일: 2026-05-23
- 상태: 설계 작성, 사용자 검토 대기
- 선행: `docs/superpowers/specs/2026-05-22-fido2-core-self-implementation-design.md` (전체 설계), Milestone A 완료
- 관련: `docs/architecture.md`, `docs/superpowers/plans/2026-05-22-fido2-core-self-implementation-milestone-a.md`

## 1. 목표

Milestone A에서 strict(mdsStrict) 등록 경로용으로 남겨둔 webauthn4j를 자체 구현으로 완전히 교체한다. `webauthn4j-core`·`webauthn4j-metadata` 의존성을 production에서 완전히 제거하여, 전체 WebAuthn 검증(인증 + 등록 strict/non-strict 전체)이 자체 FIDO2 코어(`com.crosscert.passkey.fido2`)로 동작하게 한다.

전체 설계(`2026-05-22-fido2-core-self-implementation-design.md`)의 Phase 3·4에 해당한다.

## 2. 배경: Milestone A 완료 시점의 상태

| | non-strict 경로 | strict(mdsStrict) 경로 | webauthn4j |
|---|---|---|---|
| Milestone A 완료 후 (현재) | 자체 코어 | webauthn4j (`verifyWithWebauthn4j`) | 잔존 (`webauthn4j-core`·`webauthn4j-metadata`) |
| Milestone B 완료 후 | 자체 코어 | 자체 코어 + 자체 MDS | 완전 제거 |

- 자체 코어는 `none`과 `packed`(self + full attestation) 포맷을 검증한다. `packed` full 경로는 WebAuthn L3 §8.2.1 cert 정합성(X.509 v3·CA=false·subject-OU·AAGUID 확장 일치)은 검증하지만 **cert chain trust anchor 검증은 하지 않는다**.
- strict 경로는 `RegistrationService.verifyWithWebauthn4j()`가 webauthn4j strict `WebAuthnManager`로 cert chain + MDS trust anchor 검증을 수행한다.
- MDS는 webauthn4j의 `FidoMDS3MetadataBLOBProvider`가 HTTPS fetch + BLOB JWT 서명검증 + 캐싱을 담당한다.

## 3. 범위

### Phase 3 — MDS 인프라 + cert-path 검증 + 단순 attestation 포맷
- `fido2.mds` 패키지: FIDO MDS3 BLOB(JWT) 파싱. JWT 서명검증은 nimbus-jose-jwt 재사용, payload(JSON) 해석·StatusReport·AAGUID별 trust anchor 추출은 자체 구현.
- `fido2.attestation`의 cert-path 검증 인프라: JCA `CertPathValidator`(PKIX)로 attestation cert → MDS trust anchor 체인 검증.
- attestation verifier 추가: `packed` full 경로에 trust anchor 검증 추가, `apple`(apple-anonymous), `android-key`.

### Phase 4 — 복잡 포맷 + webauthn4j 완전 제거
- attestation verifier 추가: `android-safetynet`(JWS 기반 — nimbus 재사용), `fido-u2f`, `tpm`(TPMS_ATTEST 파싱, pubArea 일치, AIK cert EKU·SAN — 가장 복잡).
- `RegistrationService.verifyWithWebauthn4j()` 제거 → strict 경로도 자체 코어로 통합, `verifyWithCore` 단일 경로.
- `webauthn4j-core`·`webauthn4j-metadata` 의존성 삭제, `WebAuthnConfig`·`MdsTrustAnchorRepositoryConfig` 정리, `credential/metadata/*` 재배선.
- 차등 테스트를 골든 벡터 기반으로 전환.

### 범위 외 (YAGNI)
- FIDO conformance 공식 인증 획득.
- EdDSA 등 ES256/RS256 외 알고리즘.
- 별도 npm/Maven 패키지 출시.

## 4. MDS 인프라 (`fido2.mds` 패키지)

### 4.1 책임 분리

webauthn4j의 `FidoMDS3MetadataBLOBProvider`가 통합 처리하던 일을 계층별로 나눈다.

- **HTTPS fetch**: Spring `RestClient` — 단순 GET. `credential.metadata` 인프라 계층 (fido2 코어 아님).
- **JWT 서명검증**: nimbus-jose-jwt. MDS3 BLOB은 `x5c` 헤더에 cert chain을 담은 JWS. nimbus가 JWS 파싱 + RS256 서명검증, x5c 체인을 JCA `CertPathValidator`로 FIDO Alliance Global Root CA까지 검증.
- **payload 해석**: `fido2.mds` 자체 구현. BLOB payload(JSON)를 레코드로 파싱.

### 4.2 `fido2.mds` 패키지 구성 (신규 — Spring 무관, 코어)

| 파일 | 책임 |
|------|------|
| `MetadataBlob.java` | 파싱된 BLOB — payload + 검증 시각. `parse(jwsString, rootCa)` 정적 메서드 |
| `MetadataEntry.java` | AAGUID별 엔트리 — aaguid, trust anchor 인증서들, statusReports |
| `StatusReport.java` | FIDO 인증 상태. `REVOKED`/`ATTESTATION_KEY_COMPROMISE` 등 critical 상태 판정 |
| `MdsTrustAnchorSource.java` | AAGUID → `Set<X509Certificate>` trust anchor 조회. attestation verifier가 cert-path 검증 시 사용 |

### 4.3 `credential.metadata` 인프라 계층 (Spring — 유지·재배선)

| 클래스 | Milestone B 처리 |
|--------|------------------|
| `MdsRefreshScheduler` | 유지 — `@Scheduled` 스케줄 로직(cron, stale 유지, 실패 처리) 불변. webauthn4j 무관 |
| `MdsBlobProvider` | Phase 3: 자체 `fido2.mds.MetadataBlob.parse()` 파싱을 병행 추가(RestClient fetch), webauthn4j `FidoMDS3MetadataBLOBProvider` delegate는 strict 경로용으로 잔존. Phase 4: strict 경로 전환 완료 후 webauthn4j delegate 제거. lifecycle·캐싱·`/_diag` 노출은 유지 |
| `MdsTrustAnchorRepositoryConfig` | **Phase 4에서 제거** — webauthn4j `TrustAnchorRepository` 전용 wiring이며 strict `WebAuthnManager`가 이 빈에 의존하므로 strict 경로가 webauthn4j로 남는 Phase 3 동안은 유지해야 한다. Phase 3는 자체 `MdsTrustAnchorSource` 빈을 노출하는 `MdsConfig`를 **병행 추가**한다 |
| `MdsProperties` | 유지 (webauthn4j 타입 미사용 확인 필요 — 미사용이면 그대로) |
| `MdsDiagController` | 유지 (webauthn4j 타입 미사용 확인 필요) |

### 4.4 BLOB 갱신 흐름

```
MdsRefreshScheduler (@Scheduled 일 1회, 로직 불변)
  → MdsBlobProvider.refresh() (내부 교체)
      → RestClient: GET mds3.fidoalliance.org → JWS 문자열
      → fido2.mds.MetadataBlob.parse(jws, fidoRootCa)
          → nimbus: JWS 파싱 + RS256 서명검증 + x5c 체인
          → JCA CertPathValidator: x5c → FIDO Global Root CA 체인 검증
          → payload(JSON) → MetadataEntry 목록
      → MdsTrustAnchorSource 적재 (AtomicReference 스왑)
  실패 시 stale BLOB 유지 (현 정책 그대로)
```

### 4.5 경계 규칙

`fido2.mds`가 nimbus-jose-jwt를 import한다. Milestone A에서 `fido2`는 "순수 Java + JCA + Jackson"이었으나 nimbus가 추가된다. nimbus는 Jackson처럼 라이브러리(Spring·도메인 아님)이므로 ArchUnit Rule 7(Spring·도메인 import 금지)에 위배되지 않는다. Rule 7 주석에 "nimbus-jose-jwt는 MDS BLOB JWS 검증용으로 허용"을 명시한다. fetch/스케줄링은 `fido2.mds`가 아니라 `credential.metadata` 인프라 계층에 둔다 (Spring `@Component`·`@Scheduled` 필요 — 코어는 Spring 금지).

## 5. attestation verifier 확장

### 5.1 trust anchor 검증을 verifier에 넣는 방식

코어의 경계 원칙(코어는 검증만, 정책은 호출자)을 지키기 위해, verifier는 `mdsStrict` 정책을 직접 알지 않는다. 대신 `AttestationVerifier.verify()`가 선택적(nullable) `MdsTrustAnchorSource`를 파라미터로 받는다.

- `trustAnchorSource == null` (non-strict): cert 정합성·서명만 검증 (Milestone A 동작).
- `trustAnchorSource != null` (strict): 추가로 AAGUID로 trust anchor를 조회해 JCA `CertPathValidator`로 cert chain 검증.

호출자(`RegistrationService`)가 `policy.isMdsStrict()`에 따라 source를 넘기거나 null을 넘긴다. 정책 판단은 호출자에 남고, 코어는 "source가 있으면 검증"만 한다.

### 5.2 인터페이스 변경

- `AttestationVerifier.verify(AttestationObject, byte[] clientDataHash, MdsTrustAnchorSource trustAnchors)` — 세 번째 파라미터 추가(nullable). sealed `permits` 절에 신규 verifier 추가.
- `AttestationVerifiers` 레지스트리에 fmt 6종 등록.
- `RegistrationVerificationRequest`에 `MdsTrustAnchorSource` 필드 추가(nullable). `RegistrationVerifier`가 그것을 `AttestationVerifier.verify()`에 전달.

### 5.3 Phase별 verifier 구성 (`fido2.attestation`)

| Phase | verifier | 핵심 |
|-------|----------|------|
| 3 | `PackedAttestationVerifier` (확장) | full 경로에 trust anchor 검증 추가 (§8.2.1 정합성은 이미 있음) |
| 3 | `AppleAnonymousAttestationVerifier` | apple. nonce 확장(`1.2.840.113635.100.8.2`) ↔ `authData‖clientDataHash` SHA-256 일치 |
| 3 | `AndroidKeyAttestationVerifier` | android-key. x5c 첫 cert의 key attestation 확장 검증 |
| 4 | `AndroidSafetyNetAttestationVerifier` | android-safetynet. response가 JWS — nimbus로 검증 |
| 4 | `FidoU2fAttestationVerifier` | fido-u2f. 레거시 — U2F 공개키 형식 |
| 4 | `TpmAttestationVerifier` | tpm. `TPMS_ATTEST`·`TPMT_PUBLIC` 파싱, pubArea ↔ credential 키 일치, AIK cert EKU·SAN |

## 6. 데이터 흐름

### 6.1 등록 흐름 (Milestone B 완료 후 — strict/non-strict 단일화)

```
RegistrationService.finishRegistration(req)
  1. challenge consume, ceremonyType 검증              (그대로)
  2. policy 조회 (TenantAttestationPolicy)             (그대로)
  3. MdsTrustAnchorSource 결정:
       policy.isMdsStrict() == true  → mdsTrustAnchorSource 빈
       policy.isMdsStrict() == false → null
       (mdsStrict인데 MDS 미적재 → MDS_UNAVAILABLE — 현 동작 유지)
  4. RegistrationVerificationRequest 조립 (+ trustAnchorSource 필드)
  5. verifyWithCore(req, trustAnchorSource)            ← 단일 경로
       → RegistrationVerifier
       → AttestationVerifier.verify(obj, hash, trustAnchorSource)
       → RegistrationVerificationResult
  6. 결과로 정책 판단: AAGUID 허용·syncable             (그대로)
  7. Credential.create + audit + metrics              (그대로)
```

`verifyWithWebauthn4j()`는 삭제된다. `if (policy.isMdsStrict())` 분기는 매니저 선택이 아니라 `MdsTrustAnchorSource`를 넘길지 null을 넘길지의 분기로 축소된다. `AttestationFacts` private record는 두 경로를 통일할 필요가 없어지므로 `RegistrationVerificationResult`를 직접 쓰도록 단순화한다.

### 6.2 MDS 실패 처리 (현 동작 보존)

- `mdsStrict=true`인데 BLOB을 한 번도 못 가져옴 → `MDS_UNAVAILABLE` (fail-closed).
- BLOB은 있으나 attestation의 AAGUID가 trust anchor에 없음 → `MDS_TRUST_FAILED`.
- StatusReport가 `REVOKED`/`ATTESTATION_KEY_COMPROMISE` 등 critical → `AUTHENTICATOR_REVOKED`.
- 이 3개 `ErrorCode`는 Milestone A에 이미 존재한다.

## 7. 에러 처리

- 자체 코어는 Milestone A와 동일하게 `Fido2VerificationException(FailureReason, message)`만 던진다.
- `FailureReason`에 enum 값 추가: `TRUST_PATH_INVALID`(cert chain → MDS anchor 검증 실패), `MDS_TRUST_FAILED`(AAGUID가 trust anchor에 없음), `AUTHENTICATOR_REVOKED`(StatusReport critical), `MDS_BLOB_INVALID`(BLOB JWS/payload 파싱 실패).
- 호출자(`RegistrationService`)가 `FailureReason` → 기존 `ErrorCode`(`MDS_TRUST_FAILED`/`MDS_UNAVAILABLE`/`AUTHENTICATOR_REVOKED`)로 매핑. 코어는 여전히 `BusinessException`/`ErrorCode`를 모른다 (ArchUnit Rule 7).
- MDS BLOB 미적재 시 `MDS_UNAVAILABLE` fail-closed — 현 동작 보존.

## 8. 테스트 전략

### 8.1 골든 벡터 (차등 테스트 대체)

webauthn4j를 제거하면 `AssertionDifferentialTest`/`RegistrationDifferentialTest`의 비교 대상이 사라진다. 대체 안전망:

- FIDO Alliance conformance 테스트 벡터 + W3C 명세 예제 + 실기기 캡처(YubiKey/iCloud/Windows Hello/Android) attestationObject를 `src/test/resources`에 고정 골든 벡터로 보관.
- 각 attestation 포맷별로 알려진 입력 → 기대 출력 검증.
- 차등 테스트는 webauthn4j 의존성을 production에서 제거하는 마지막 단계(Phase 4)에서 골든 벡터 기반으로 전환한다 (삭제가 아니라 교체).

### 8.2 MDS 테스트

- 실제 FIDO MDS3 BLOB 스냅샷을 고정 fixture로. 만료된 BLOB·변조된 BLOB·critical StatusReport 엔트리 케이스.

### 8.3 strict 경로 통합 테스트 신규 추가

현재 등록 ceremony의 happy-path를 검증하는 슬라이스/통합 테스트가 없다 (`RegistrationServiceTest`는 fail-closed 분기만 검증). Milestone B에서 strict 경로를 자체 코어로 교체하면서, `integration/credential/`에 strict 등록 통합 테스트를 신규 추가한다 — Oracle DB + `passkey.mds.enabled=true` + 고정 MDS BLOB fixture로, `mdsStrict=true` 테넌트의 attestation 등록이 자체 코어로 end-to-end 통과/거부되는지 검증. `AdminEnabledIntegrationTestBase`처럼 `@DynamicPropertySource`로 MDS 활성화.

### 8.4 회귀 감지 — integration 테스트로 webauthn4j 제거 영향 검증

기존 `integration/` 테스트(테넌트 격리·admin 영역)는 webauthn4j도 attestation도 import하지 않으므로 Milestone B의 직접 영향은 없다. 그러나 webauthn4j 제거는 Spring context 구성·transitive 의존성·`build.gradle.kts`를 바꾸므로 무관한 통합 테스트를 간접적으로 깰 수 있다 (context 미기동, transitive 의존성 소실 등). 이를 보장으로 바꾸는 방법:

1. **베이스라인 고정**: Milestone B 시작 전 `./gradlew check` 통과 상태가 baseline (Milestone A 마무리 시 확인된 상태).
2. **Phase별 전체 회귀 검증**: Phase 3·4의 각 단계 끝에서 `./gradlew check`(unit + integration + ArchUnit + spotless) 전체 실행. 일부만 돌리지 않는다 — integration 테스트가 회귀 감지기 역할.
3. **webauthn4j 제거 단계 전용 게이트**: Phase 4에서 `webauthn4j-core`·`webauthn4j-metadata` 의존성 삭제 커밋 직후 — `./gradlew check` 통과 + `git diff`로 transitive 의존성 변화 확인을 명시적 검증 단계로 둔다.
4. **Spring context 회귀 보호**: `WebAuthnConfig` 제거·`MdsTrustAnchorRepositoryConfig` 교체 직후 컨텍스트를 띄우는 통합 테스트가 통과하는지 확인. context 깨짐은 무관한 통합 테스트에서 먼저 터지므로 integration 테스트가 감지기가 된다.

### 8.5 기타

- 통합 테스트: 기존 `RegistrationServiceTest` + strict 경로 슬라이스 테스트가 자체 코어로 통과.
- `RegistrationServiceTest`/`AuthenticationServiceTest`가 커버하는 분기가 strict 경로 교체 후에도 유효한지 Phase 4에서 점검.

## 9. 의존성 정리

| 의존성 | 분류 | Milestone B 처리 |
|--------|------|------------------|
| `webauthn4j-core` | `implementation` (production) | 완전 제거 — Milestone B 핵심 목표 |
| `webauthn4j-metadata` | `implementation` (production) | 완전 제거 |
| `nimbus-jose-jwt` | `implementation` (production, 기존) | 유지 — MDS3 BLOB JWS 검증에 재사용 |
| `bcpkix-jdk18on` (BouncyCastle) | `testImplementation` (test) | 유지 — 테스트 attestation cert fixture 생성용. production 미포함이며 webauthn4j 제거 목표와 무관. Milestone B 테스트 작성에 계속 사용 |

production cert-path 검증은 JCA `CertPathValidator`(JDK 표준)를 쓴다. BouncyCastle을 production cert 검증에 끌어들이지 않는다 — `org.bouncycastle`은 Milestone B 후에도 test에만 머문다.

## 10. 완료 기준 (Milestone B)

- production 코드에 `com.webauthn4j` import 0건.
- `webauthn4j-core`·`webauthn4j-metadata` 의존성 `build.gradle.kts`에서 삭제.
- strict/non-strict 등록 경로 모두 자체 코어 (`verifyWithWebauthn4j` 제거, `verifyWithCore` 단일화).
- 6개 attestation 포맷(packed-full / apple / android-key / android-safetynet / fido-u2f / tpm) 자체 검증.
- `fido2.mds` 패키지로 MDS3 BLOB 자체 파싱·trust anchor 조회.
- `WebAuthnConfig`·`MdsTrustAnchorRepositoryConfig` 정리, `credential/metadata/*` 재배선.
- strict 경로 통합 테스트 신규 추가 (Oracle DB + MDS BLOB fixture).
- 차등 테스트를 골든 벡터 기반으로 전환.
- ArchUnit Rule 7 통과 (nimbus 허용 주석 반영).
- `./gradlew check` 전체 통과.
- `docs/architecture.md` §11 변경 이력 갱신.

## 11. Phase 4 상세 결정 (2026-05-23 brainstorming)

Phase 3 완료 후 Phase 4 plan 작성을 위해 추가로 합의된 결정 사항. 위 §3·§5·§6와 일관되며 그것을 구체화한다.

### 11.1 Task 묶음 전략
verifier 3종(android-safetynet / fido-u2f / tpm)을 **먼저** 모두 추가한 뒤 strict 경로를 단일화하고 webauthn4j를 제거한다. 그래야 webauthn4j를 떼어내는 시점에 자체 코어가 6포맷 모두를 처리할 수 있어 회귀 위험이 최소화된다.

### 11.2 TPM 지원 범위
- **TPM 2.0만 완전 구현**. `attStmt.ver == "1.2"`은 `Fido2VerificationException(UNSUPPORTED_ATTESTATION_FORMAT)`로 거부한다. Windows Hello 등 상용 TPM은 모두 2.0이며 TPM 1.2는 2016년 이전 레거시 하드웨어용으로 현장에서 거의 보지 못한다 — YAGNI.
- TPM 2.0 검증 단계: (1) `attStmt` 필수 필드 추출 + `ver=2.0` (2) `pubArea` 파싱 → credential public key와 동일성 (3) `certInfo` 파싱 → `magic == TPM_GENERATED_VALUE(0xFF544347)`, `type == TPM_ST_ATTEST_CERTIFY`, `extraData == SHA-256(authData || clientDataHash)`, `attested.name == TPMT_HA(SHA-256(pubArea))` (4) AIK cert(x5c[0])로 `sig`가 `certInfo` 서명했는지 (5) AIK cert 정합성 — v3, EKU에 `2.23.133.8.3`, SAN에 `2.23.133.2.{1,2,3}` (manufacturer/model/version), basicConstraints CA=false, AAGUID 확장 일치 (6) strict 시 x5c → MDS trust anchor PKIX.
- TPM 이진 파서는 `fido2.tpm` 서브패키지로 분리(`TpmsAttest.parse`·`TpmtPublic.parse` 단위 테스트 가치 큼).

### 11.3 골든 벡터 출처
차등 테스트 교체용 골든 벡터는 다음 3계층 조합으로 구성한다:
- **W3C WebAuthn L2·L3 명세 예제**: 라이선스 깨끗, binary-level 명시 — "외부 표준 입력 → 우리 코어 동일 결과"를 보장하는 핵심.
- **BouncyCastle 자체 생성 (포맷별)**: Phase 3와 동일 패턴 — 6포맷 각각 self-signed cert + attestationObject 생성. 자체 빌드만으로 재현 가능.
- **FIDO Alliance conformance 벡터 (공개 가능분, 포맷별 1~2개)**: 공식 근거 강화. 라이선스 확인 후 가능한 만큼만.
- **실기기 캡처는 YAGNI** — Phase 4 범위 외, QA 환경에서 점진 수집.

### 11.4 webauthn4j 제거 안전장치 — 단계적 제거
import → config → provider delegate → controller 점검 → build.gradle 순으로 단계 분리. 각 단계 끝에서 `./gradlew check` 통과 확인. 의존성 파일 삭제(`build.gradle.kts`)는 **마지막**에 한다. 실패 시 원인 특정이 쉽고 git revert 한 커밋으로 되돌릴 수 있다.

### 11.5 strict 경로 통합 테스트 폭
신규 `RegistrationStrictIntegrationTest`(가칭)에 6개 fmt(packed/apple/android-key/android-safetynet/fido-u2f/tpm) 각각:
- happy-path 1건 (해당 fmt가 MDS-등록된 AAGUID로 등록 성공)
- 거부 1건 (MDS_TRUST_FAILED 또는 AUTHENTICATOR_REVOKED 중 fmt 특성에 맞는 것)

= 총 12 test methods. `none`은 strict가 통과시켜야 하므로 별도 추가(1건). MDS BLOB fixture는 BouncyCastle로 생성한 자체 root CA + entries 묶음을 `src/test/resources/fido2/mds-blob-fixture.jws`로 고정.

### 11.6 후속 클린업 포함 범위
Phase 4에 포함:
- `AttestationTestCerts` 공용 헬퍼 추출 (Apple/Android Key/Packed/신규 3종 테스트의 `selfSignedCa`/`leafOf`/`aaguidOfAttestation` 중복 제거)
- `DerUtil` 단위 테스트 추가 (현재 verifier 테스트가 간접 커버 — 직접 커버 필요)
- 기존 strict 테스트들의 인라인 FQN(`com.crosscert.passkey.fido2.mds.*`) → 정식 import 정리
- `FailureReason.UNSUPPORTED_ALGORITHM` 정리 (미사용이면 enum에서 삭제, tpm에서 사용처 생긴다면 명시 사용)

Phase 4에서 제외:
- **cross-origin 정책**: `RegistrationVerificationResult.crossOrigin()` 값을 활용해 `RegistrationService`에서 정책 거부 결정 — webauthn4j 교체와 무관한 도메인 정책 변경이므로 별도 작업(Milestone C 또는 backlog).

### 11.7 신규 `FailureReason` 값
- `INVALID_ATTESTATION_FORMAT`: 신규 — `tpm` `ver=1.2` 등 verifier가 인식 가능하지만 정책상 거부.
- `INVALID_TPM_STRUCTURE`: 신규 — TPMS_ATTEST / TPMT_PUBLIC 파싱 실패 또는 일관성 위반.
- 기존 재사용: `TRUST_PATH_INVALID` / `MDS_TRUST_FAILED` / `AUTHENTICATOR_REVOKED` / `MDS_BLOB_INVALID` (이미 enum에 존재) / `ATTESTATION_INVALID` / `SIGNATURE_INVALID` / `UNSUPPORTED_ALGORITHM`(정리 대상).
