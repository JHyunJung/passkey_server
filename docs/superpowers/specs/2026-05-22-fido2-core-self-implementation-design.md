# FIDO2 코어 자체 구현 설계

- 작성일: 2026-05-22
- 상태: 설계 승인 완료, 구현 계획 작성 대기
- 관련 문서: `docs/architecture.md`, `docs/capability-spec.md`

## 1. 목표

WebAuthn 검증을 외부 라이브러리 `webauthn4j`에 의존하지 않고 [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) 명세를 직접 구현한 자체 FIDO2 코어로 단계적으로 교체한다. 코어는 `com.crosscert.passkey.fido2` 패키지로 분리하고, ArchUnit으로 경계를 강제한다.

### 동기
- **의존성 제거 / 자체 통제**: 외부 라이브러리 의존을 없애고 FIDO2 검증 로직을 직접 통제·감사한다.
- **라이브러리 한계 / 커스터마이징**: 확장·attestation 포맷·정책 커스터마이징의 자유를 확보한다.
- **패키지 분리**: FIDO2 코어를 도메인 코드와 분리된 깨끗한 모듈 경계로 만든다.

## 2. 범위

### Milestone A (1차 목표)
- Phase 0: 코어 빌딩블록 (CBOR/COSE/model)
- Phase 1: 인증(assertion) 경로 자체 코어 교체
- Phase 2: 등록(none / packed-self attestation) 경로 자체 코어 교체
- 완료 시 `webauthn4j-core` 의존성 제거

### Milestone B (후속)
- Phase 3: packed-full / apple / android-key attestation + X.509 cert path 검증
- Phase 4: TPM / android-safetynet / U2F attestation + FIDO MDS3 BLOB 파싱·trust anchor
- 완료 시 `webauthn4j-metadata` 의존성 제거

### 범위 외 (YAGNI)
- 별도 npm/Maven 패키지 출시 — 동일 모듈 내 패키지 분리로 충분
- FIDO conformance 공식 인증 획득
- EdDSA 등 ES256/RS256 외 알고리즘 (필요 시 후속)

## 3. 아키텍처와 패키지 경계

### 패키지 구조 (신규)

```
com.crosscert.passkey.fido2          순수 WebAuthn L3 코어. Spring·도메인 의존 0
├── cbor/         CBOR 디코더 (RFC 8949 subset — WebAuthn에 필요한 만큼만)
├── cose/         COSE 키 디코딩 + 서명 검증 (ES256/RS256)
├── model/        AuthenticatorData, AttestedCredentialData, CollectedClientData,
│                 AttestationObject 등 불변 레코드
├── attestation/  AttestationVerifier 인터페이스 + 포맷별 구현
├── RegistrationVerifier      navigator.credentials.create() 결과 검증
└── AuthenticationVerifier    navigator.credentials.get() 결과 검증
```

### 경계 규칙 (ArchUnit 신규 룰로 강제)

1. `fido2` 패키지는 `credential`·`tenant`·`audit`·`common`·`admin`·`auth` 등 어떤 도메인 패키지도 import 금지.
2. `fido2` 패키지는 Spring(`org.springframework.*`)·`common.exception` import 금지. 순수 Java + JCA(`java.security`)만 사용.
3. 의존 방향은 단방향: `credential.service` → `fido2`. 역방향 금지.
4. `fido2`는 멀티테넌트 정책을 모른다. 입력으로 받은 challenge/origin/rpId로 명세 검증만 하고, 검증된 사실을 결과 레코드로 반환한다. AAGUID 허용목록·syncable·mdsStrict 판단은 `RegistrationService`에 그대로 남는다.

### MDS의 위치

FIDO MDS3 BLOB 파싱·trust anchor 매칭은 attestation cert path 검증에 필요하므로 `fido2.attestation.mds` 하위에 들어간다. 단, Milestone B에서 다루며 그때까지 기존 `credential/metadata/*`는 그대로 유지한다.

## 4. 컴포넌트와 인터페이스 (Milestone A 범위)

### 4.1 `fido2.cbor` — CBORDecoder

- 입력 `byte[]` → 출력 `Object` (Map/List/byte[]/Long/Boolean/String 트리)
- WebAuthn에 필요한 major type만 구현: unsigned int, negative int, byte string, text string, array, map. float/tag는 attestation에 필요한 최소만.
- `attestationObject`가 trailing bytes를 가질 수 있으므로 "소비한 바이트 수"를 함께 반환하는 변형을 제공한다.
- WebAuthn subset 외 입력은 명시적으로 거부 → `MALFORMED_CBOR` (fail-closed).

### 4.2 `fido2.cose` — CoseKey / CoseSignatureVerifier

- `CoseKey.parse(Map)` → kty/alg/curve + 공개키 파라미터. ES256(-7), RS256(-257) 지원.
- `verify(CoseKey, byte[] signedData, byte[] signature)` → `boolean`. JCA `Signature`로 검증.
- ES256: 인증기가 보내는 ASN.1 DER ECDSA 서명을 JCA `Signature("SHA256withECDSA")`에 그대로 전달 — 수동 DER 파싱 없음.

### 4.3 `fido2.model` — 불변 레코드

- `AuthenticatorData`: rpIdHash, flags(UP/UV/BE/BS/AT/ED), signCount, attestedCredentialData?, extensions?
- `AttestedCredentialData`: aaguid, credentialId, coseKey(원본 bytes + 파싱본). `parse(byte[])` 정적 메서드 제공.
- `CollectedClientData`: type, challenge, origin, crossOrigin, tokenBinding?
- `AttestationObject`: fmt, attStmt(Map), authData

### 4.4 `fido2.attestation` — AttestationVerifier

```java
sealed interface AttestationVerifier {
  String format();                        // "none", "packed"
  AttestationResult verify(AttestationObject obj, byte[] clientDataHash);
}
```

- Milestone A 구현체: `NoneAttestationVerifier`, `PackedSelfAttestationVerifier` (x5c 없는 self attestation만; x5c 있는 full attestation은 Milestone B).
- 레지스트리가 `fmt` 문자열로 디스패치. 미지원 포맷은 `UNSUPPORTED_ATTESTATION_FORMAT`.

### 4.5 `fido2.RegistrationVerifier`

- 입력 `RegistrationVerificationRequest`: attestationObject, clientDataJSON, expectedChallenge, expectedOrigins, expectedRpId, userVerificationRequired
- 출력 `RegistrationVerificationResult`: credentialId, coseKey bytes, aaguid, signCount, beFlag, bsFlag, uvFlag, attestationFormat

### 4.6 `fido2.AuthenticationVerifier`

- 입력 `AuthenticationVerificationRequest`: authenticatorData, clientDataJSON, signature, expectedChallenge, expectedOrigins, expectedRpId, storedCoseKey, userVerificationRequired
- 출력 `AuthenticationVerificationResult`: newSignCount, uvFlag, beFlag, bsFlag
- signCount 회귀 판정은 코어가 하지 않는다. `newSignCount`를 반환하고 `Credential.updateSignatureCounter()`의 기존 로직이 판단한다.

### 4.7 에러 처리

- 코어 검증 실패는 `Fido2VerificationException` (체크 예외, `FailureReason` enum 보유).
- `FailureReason` 값: `CHALLENGE_MISMATCH`, `ORIGIN_MISMATCH`, `RPID_HASH_MISMATCH`, `UP_FLAG_MISSING`, `UV_FLAG_REQUIRED`, `SIGNATURE_INVALID`, `UNSUPPORTED_ALGORITHM`, `MALFORMED_CBOR`, `UNSUPPORTED_ATTESTATION_FORMAT` 등.
- 코어는 절대 `BusinessException`을 던지지 않는다 (ArchUnit으로 강제). 호출자가 `FailureReason` → `ErrorCode`로 매핑하며, 대부분 `ATTESTATION_INVALID`/`ASSERTION_INVALID`로 수렴하되 로그에는 상세 사유를 기록한다 (기존 `log.warn` 패턴 유지).

## 5. 단계적 구현 로드맵

각 Phase는 독립 PR이며, 끝마다 `./gradlew check`가 통과하고 webauthn4j에서 해당 부분만 점진 제거된다. 언제 멈춰도 완전한 상태다.

### Phase 0 — 기반 (webauthn4j 유지, 추가만)
- `fido2.cbor` CBOR 디코더 + 공개 테스트 벡터 검증
- `fido2.cose` COSE_Key 디코딩, ES256/RS256 서명 검증
- `fido2.model` 불변 레코드
- webauthn4j와 병행 — 아직 교체하지 않고 빌딩블록만 확보

### Phase 1 — 인증(assertion) 경로 교체
- `AuthenticationVerifier` 구현: clientDataJSON 파싱, challenge/origin/rpIdHash/UV 플래그 검증, COSE 공개키 서명 검증
- `AttestedCredentialData.parse(byte[])` 구현 — DB의 `credential.public_key_cose`(webauthn4j `AttestedCredentialDataConverter` 직렬화 형식)를 읽는다. 이 형식은 WebAuthn authData의 attestedCredentialData 구조(AAGUID 16B + credIdLen 2B + credId + COSE key) 그 자체라 명세 기반으로 그대로 파싱 가능 — 마이그레이션·백필 불필요.
- `AuthenticationService.verifyAssertion()`만 자체 코어로 교체
- 기존 DB 실데이터로 회귀 테스트 포함

### Phase 2 — 등록(none / packed-self) 경로 교체
- `RegistrationVerifier` + `AttestationVerifier` 인터페이스, `none`/`packed`(self-attestation) 구현
- `RegistrationService.finishRegistration()`을 자체 코어로 교체
- 완료 시 `webauthn4j-core` 의존성 제거 가능

### Phase 3 — packed-full / apple / android-key + cert path (Milestone B)
- X.509 cert chain 검증(JCA `CertPath` API), packed full attestation, apple-anonymous, android-key
- AAGUID ↔ 인증기 검증

### Phase 4 — TPM / android-safetynet / U2F + MDS3 (Milestone B)
- 가장 복잡한 포맷 + FIDO MDS3 BLOB(JWT) 파싱·trust anchor
- 완료 시 `webauthn4j-metadata` 의존성 완전 제거, `WebAuthnConfig`·`credential/metadata/*` 정리

## 6. 데이터 흐름

### 등록 흐름 (Phase 2 이후)

```
RegistrationService.finishRegistration(req)
  1. challenge consume, ceremonyType 검증                (기존 그대로)
  2. RegistrationVerificationRequest 조립
       expectedChallenge          ← stored.challengeB64u
       expectedOrigins            ← cfg.originList()
       expectedRpId               ← cfg.getRpId()
       userVerificationRequired   ← cfg.getUserVerification().isStrictRequired()
  3. RegistrationVerifier.verify(request)                ← 자체 코어
       → RegistrationVerificationResult
  4. 결과로 정책 판단 (코어 밖, 기존 로직 유지):
       policy.accepts(result.aaguid())                   → AAGUID_NOT_ALLOWED
       policy.acceptsSyncable(result.beFlag())            → SYNCABLE_NOT_ALLOWED
  5. Credential.create(... result.coseKey(), result.signCount() ...)
  6. audit + metrics                                     (기존 그대로)
```

`Fido2VerificationException` → `BusinessException(ErrorCode.ATTESTATION_INVALID)` 매핑은 `RegistrationService` 안의 try-catch에서 수행한다.

### 인증 흐름 (Phase 1 이후)

`verifyAssertion()`만 교체:

```
저장된 credential.getPublicKeyCose()  (webauthn4j AttestedCredentialData 직렬화 형식)
  → AttestedCredentialData.parse(byte[]) → CoseKey
  → AuthenticationVerifier.verify(request) → AuthenticationVerificationResult
```

## 7. 테스트 전략

- **코어 단위 테스트**: webauthn4j 의존 없는 순수 단위 테스트. 공개 테스트 벡터(W3C 명세 예제, FIDO conformance 샘플) + 실제 인증기 캡처 데이터.
- **차등 테스트(differential test)**: Phase 1·2 동안 동일 입력을 webauthn4j와 자체 코어에 모두 넣어 결과 일치를 확인한다. webauthn4j 제거 전까지 이 테스트가 안전망 역할을 한다.
- **통합 테스트**: 기존 `RegistrationServiceTest`/`AuthenticationServiceTest`가 그대로 통과해야 한다 (호출자 인터페이스 불변).
- **ArchUnit**: `fido2` → 도메인/Spring/`common.exception` import 금지 룰 추가 (§3 경계 규칙).

## 8. 리스크와 대응

| 리스크 | 대응 |
|---|---|
| 자체 암호 검증 버그 = 보안 취약점 | 차등 테스트(webauthn4j 병행)를 Milestone A 내내 유지. W3C/FIDO 공개 벡터. Phase별 PR 코드리뷰 |
| DB의 webauthn4j 직렬화 형식 호환 | `AttestedCredentialData.parse()` + 기존 실데이터 회귀 테스트 (Phase 1) |
| ES256 ASN.1 DER 서명 처리 실수 | JCA `Signature("SHA256withECDSA")`가 DER을 직접 수용 — 수동 파싱 안 함 |
| CBOR 디코더의 미지원 입력 | WebAuthn subset만 구현, 그 외는 `MALFORMED_CBOR`로 명시적 거부 (fail-closed) |

## 9. 완료 기준

### Milestone A
- `webauthn4j-core` 의존성 제거
- 인증 + none/packed-self 등록이 자체 코어로 동작
- `webauthn4j-metadata`는 잔존 (MDS는 Milestone B) → `WebAuthnConfig`의 strict 매니저, `credential/metadata/*`는 유지
- `./gradlew check` 통과, 차등 테스트 통과, ArchUnit 경계 룰 통과

### Milestone B
- `webauthn4j-metadata` 의존성 제거
- 전체 attestation 포맷 + MDS3 자체 코어 동작
- `WebAuthnConfig`·`credential/metadata/*` 정리, `docs/architecture.md` §10 변경 이력 갱신
