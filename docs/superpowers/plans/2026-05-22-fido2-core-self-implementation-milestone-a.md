# FIDO2 코어 자체 구현 — Milestone A 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** webauthn4j의 인증(assertion) 및 none/packed-self 등록(attestation) 검증을 자체 구현 FIDO2 코어(`com.crosscert.passkey.fido2`)로 교체하고 `webauthn4j-core` 의존성을 제거한다.

**Architecture:** 순수 Java + JCA만 사용하는 `fido2` 패키지를 신규 작성한다. 코어는 명세 검증만 수행하고 검증된 사실을 불변 레코드로 반환하며, 멀티테넌트 정책 판단은 호출자(`RegistrationService`/`AuthenticationService`)에 남긴다. Phase 0(CBOR/COSE/model 빌딩블록) → Phase 1(인증 경로 교체) → Phase 2(등록 경로 교체) 순서로 진행하고, 각 Phase 동안 webauthn4j와 결과를 대조하는 차등 테스트를 안전망으로 둔다.

**Tech Stack:** Java 17, Spring Boot 3.5, JUnit 5, AssertJ, Mockito, ArchUnit 1.3, Google Java Format(Spotless), Gradle Kotlin DSL.

**범위 주의:** 이 계획은 Milestone A(Phase 0~2)만 다룬다. Phase 3·4(packed-full/apple/android-key/TPM/SafetyNet/U2F + MDS3)는 별도 계획 `docs/superpowers/plans/<date>-fido2-core-milestone-b.md`로 작성한다. 설계 근거는 `docs/superpowers/specs/2026-05-22-fido2-core-self-implementation-design.md`.

---

## 파일 구조

신규 생성 (`server/src/main/java/com/crosscert/passkey/fido2/`):

| 파일 | 책임 |
|---|---|
| `cbor/CborDecoder.java` | RFC 8949 subset 디코더. `byte[]` → Java 객체 트리. trailing-bytes 인지. |
| `cbor/CborDecodeException.java` | CBOR 디코딩 실패 (unchecked, 내부용). |
| `cose/CoseKey.java` | COSE_Key Map → kty/alg/curve + JCA `PublicKey`. ES256/RS256. |
| `cose/CoseSignatureVerifier.java` | `CoseKey` + signedData + signature → boolean. JCA `Signature`. |
| `cose/CoseException.java` | COSE 파싱/미지원 알고리즘 실패 (unchecked, 내부용). |
| `model/Flags.java` | authenticatorData flags 바이트 해석 (UP/UV/BE/BS/AT/ED). |
| `model/AuthenticatorData.java` | rpIdHash/flags/signCount/attestedCredentialData?/rawBytes. `parse(byte[])`. |
| `model/AttestedCredentialData.java` | aaguid/credentialId/coseKeyBytes/coseKey. `parse(byte[])`. |
| `model/CollectedClientData.java` | type/challenge/origin/crossOrigin. clientDataJSON 파싱. |
| `model/AttestationObject.java` | fmt/attStmt/authData. `parse(byte[])` (CBOR). |
| `attestation/AttestationVerifier.java` | `sealed interface` — format() + verify(). |
| `attestation/AttestationResult.java` | attestation 검증 결과 (format, trustPath 유무). |
| `attestation/NoneAttestationVerifier.java` | `fmt="none"` 검증. |
| `attestation/PackedSelfAttestationVerifier.java` | `fmt="packed"`, x5c 없는 self attestation만. |
| `attestation/AttestationVerifiers.java` | fmt 문자열 → verifier 디스패치 레지스트리. |
| `Fido2VerificationException.java` | 코어 공개 체크 예외 + `FailureReason` enum. |
| `RegistrationVerifier.java` | create() 결과 검증 → `RegistrationVerificationResult`. |
| `RegistrationVerificationRequest.java` | 등록 검증 입력 레코드. |
| `RegistrationVerificationResult.java` | 등록 검증 출력 레코드. |
| `AuthenticationVerifier.java` | get() 결과 검증 → `AuthenticationVerificationResult`. |
| `AuthenticationVerificationRequest.java` | 인증 검증 입력 레코드. |
| `AuthenticationVerificationResult.java` | 인증 검증 출력 레코드. |

수정:

| 파일 | 변경 |
|---|---|
| `credential/service/AuthenticationService.java` | `verifyAssertion()`를 자체 코어로 교체 (Phase 1). |
| `credential/service/RegistrationService.java` | `finishRegistration()`의 parse/verify를 자체 코어로 교체 (Phase 2). |
| `credential/webauthn/WebAuthnConfig.java` | `nonStrictWebAuthnManager` 빈 제거 (Phase 2). |
| `architecture/PackageArchitectureTest.java` | `fido2` 경계 룰(Rule 7) 추가 (Phase 0). |
| `server/build.gradle.kts` | `webauthn4j-core` 제거 (Phase 2 종료). |

테스트 (`server/src/test/java/com/crosscert/passkey/unit/fido2/`): 각 코어 클래스별 단위 테스트 + 차등 테스트.

---

## Phase 0 — 코어 빌딩블록

webauthn4j는 그대로 둔다. 빌딩블록만 추가하고 아직 교체하지 않는다.

### Task 1: CBOR 디코더

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/cbor/CborDecodeException.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/cbor/CborDecoder.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/cbor/CborDecoderTest.java`

- [ ] **Step 1: 실패 테스트 작성**

`CborDecoderTest.java`:

```java
package com.crosscert.passkey.unit.fido2.cbor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import com.crosscert.passkey.fido2.cbor.CborDecoder.DecodeResult;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CborDecoderTest {

  // RFC 8949 Appendix A 테스트 벡터.
  @Test
  void decodes_unsigned_integers() {
    assertThat(CborDecoder.decode(hex("00"))).isEqualTo(0L);
    assertThat(CborDecoder.decode(hex("17"))).isEqualTo(23L);
    assertThat(CborDecoder.decode(hex("1818"))).isEqualTo(24L);
    assertThat(CborDecoder.decode(hex("190100"))).isEqualTo(256L);
    assertThat(CborDecoder.decode(hex("1a000f4240"))).isEqualTo(1000000L);
    assertThat(CborDecoder.decode(hex("1b0000000100000000"))).isEqualTo(4294967296L);
  }

  @Test
  void decodes_negative_integers() {
    assertThat(CborDecoder.decode(hex("20"))).isEqualTo(-1L);
    assertThat(CborDecoder.decode(hex("3863"))).isEqualTo(-100L);
    assertThat(CborDecoder.decode(hex("3903e7"))).isEqualTo(-1000L);
  }

  @Test
  void decodes_byte_and_text_strings() {
    assertThat((byte[]) CborDecoder.decode(hex("4401020304")))
        .containsExactly(1, 2, 3, 4);
    assertThat(CborDecoder.decode(hex("6161"))).isEqualTo("a");
    assertThat(CborDecoder.decode(hex("6449455446"))).isEqualTo("IETF");
  }

  @Test
  void decodes_arrays_and_maps() {
    assertThat(CborDecoder.decode(hex("83010203"))).isEqualTo(List.of(1L, 2L, 3L));
    assertThat(CborDecoder.decode(hex("a201020304")))
        .isEqualTo(Map.of(1L, 2L, 3L, 4L));
    // {"a": 1, "b": [2, 3]}
    assertThat(CborDecoder.decode(hex("a26161016162820203")))
        .isEqualTo(Map.of("a", 1L, "b", List.of(2L, 3L)));
  }

  @Test
  void decodes_simple_values() {
    assertThat(CborDecoder.decode(hex("f4"))).isEqualTo(false);
    assertThat(CborDecoder.decode(hex("f5"))).isEqualTo(true);
    assertThat(CborDecoder.decode(hex("f6"))).isNull();
  }

  @Test
  void reports_consumed_byte_count_for_trailing_data() {
    // attestationObject 패턴: CBOR map 뒤에 추가 바이트가 붙을 수 있음.
    byte[] input = hex("83010203" + "ffff");
    DecodeResult result = CborDecoder.decodeWithLength(input);
    assertThat(result.value()).isEqualTo(List.of(1L, 2L, 3L));
    assertThat(result.consumed()).isEqualTo(4);
  }

  @Test
  void rejects_truncated_input() {
    assertThatThrownBy(() -> CborDecoder.decode(hex("19ff")))
        .isInstanceOf(CborDecodeException.class);
  }

  @Test
  void rejects_unsupported_major_type() {
    // major type 6 (tag) — WebAuthn subset 밖.
    assertThatThrownBy(() -> CborDecoder.decode(hex("c074")))
        .isInstanceOf(CborDecodeException.class);
  }

  private static byte[] hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.cbor.CborDecoderTest"`
Expected: 컴파일 실패 — `CborDecoder`, `CborDecodeException` 미존재.

- [ ] **Step 3: `CborDecodeException` 구현**

```java
package com.crosscert.passkey.fido2.cbor;

/**
 * Thrown when a byte sequence is not valid CBOR within the WebAuthn-required subset (RFC 8949
 * major types 0-5 and the false/true/null simple values). Unchecked — callers in the {@code fido2}
 * package translate it into a {@code Fido2VerificationException} with {@code MALFORMED_CBOR}.
 */
public class CborDecodeException extends RuntimeException {
  public CborDecodeException(String message) {
    super(message);
  }
}
```

- [ ] **Step 4: `CborDecoder` 구현**

```java
package com.crosscert.passkey.fido2.cbor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR (RFC 8949) decoder covering only the constructs WebAuthn uses: unsigned/negative
 * integers, byte strings, text strings, arrays, maps, and the false/true/null simple values.
 * Anything else (tags, floats, indefinite-length items) is rejected with {@link
 * CborDecodeException} so a malformed or hostile attestation cannot smuggle unexpected structure
 * past the verifier (fail-closed).
 */
public final class CborDecoder {

  private final byte[] data;
  private int pos;

  private CborDecoder(byte[] data) {
    this.data = data;
    this.pos = 0;
  }

  /** Decode a single CBOR data item; the entire input must be consumed. */
  public static Object decode(byte[] data) {
    CborDecoder d = new CborDecoder(data);
    Object value = d.readItem();
    if (d.pos != data.length) {
      throw new CborDecodeException("trailing bytes after CBOR item");
    }
    return value;
  }

  /** Decode a single CBOR data item, allowing trailing bytes; reports how many were consumed. */
  public static DecodeResult decodeWithLength(byte[] data) {
    CborDecoder d = new CborDecoder(data);
    Object value = d.readItem();
    return new DecodeResult(value, d.pos);
  }

  /** A decoded value paired with the number of input bytes it occupied. */
  public record DecodeResult(Object value, int consumed) {}

  private Object readItem() {
    int initial = readByte();
    int majorType = (initial >> 5) & 0x07;
    int additional = initial & 0x1f;
    return switch (majorType) {
      case 0 -> readUnsigned(additional);
      case 1 -> -1L - readUnsigned(additional);
      case 2 -> readBytes((int) readUnsigned(additional));
      case 3 -> new String(readBytes((int) readUnsigned(additional)), StandardCharsets.UTF_8);
      case 4 -> readArray((int) readUnsigned(additional));
      case 5 -> readMap((int) readUnsigned(additional));
      case 7 -> readSimple(additional);
      default -> throw new CborDecodeException("unsupported CBOR major type " + majorType);
    };
  }

  private long readUnsigned(int additional) {
    if (additional < 24) {
      return additional;
    }
    return switch (additional) {
      case 24 -> readByte() & 0xffL;
      case 25 -> readUint(2);
      case 26 -> readUint(4);
      case 27 -> readUint(8);
      default -> throw new CborDecodeException("unsupported CBOR additional info " + additional);
    };
  }

  private long readUint(int n) {
    long value = 0;
    for (int i = 0; i < n; i++) {
      value = (value << 8) | (readByte() & 0xffL);
    }
    if (value < 0) {
      throw new CborDecodeException("CBOR integer exceeds signed 64-bit range");
    }
    return value;
  }

  private List<Object> readArray(int len) {
    List<Object> out = new ArrayList<>(len);
    for (int i = 0; i < len; i++) {
      out.add(readItem());
    }
    return out;
  }

  private Map<Object, Object> readMap(int len) {
    Map<Object, Object> out = new LinkedHashMap<>();
    for (int i = 0; i < len; i++) {
      Object key = readItem();
      Object value = readItem();
      out.put(key, value);
    }
    return out;
  }

  private Object readSimple(int additional) {
    return switch (additional) {
      case 20 -> false;
      case 21 -> true;
      case 22 -> null;
      default -> throw new CborDecodeException("unsupported CBOR simple value " + additional);
    };
  }

  private int readByte() {
    if (pos >= data.length) {
      throw new CborDecodeException("unexpected end of CBOR input");
    }
    return data[pos++] & 0xff;
  }

  private byte[] readBytes(int len) {
    if (len < 0 || pos + len > data.length) {
      throw new CborDecodeException("CBOR string length exceeds input");
    }
    byte[] out = new byte[len];
    System.arraycopy(data, pos, out, 0, len);
    pos += len;
    return out;
  }
}
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.cbor.CborDecoderTest"`
Expected: PASS (7 tests).

- [ ] **Step 6: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/cbor/ server/src/test/java/com/crosscert/passkey/unit/fido2/cbor/
git commit -m "feat(fido2): WebAuthn subset CBOR 디코더 추가"
```

---

### Task 2: COSE 키 + 서명 검증

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/cose/CoseException.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/cose/CoseKey.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/cose/CoseSignatureVerifier.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/cose/CoseKeyTest.java`

- [ ] **Step 1: 실패 테스트 작성**

`CoseKeyTest.java`:

```java
package com.crosscert.passkey.unit.fido2.cose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecoder;
import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CoseKeyTest {

  @Test
  void parses_es256_key_and_verifies_signature() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = gen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) pair.getPublic();

    byte[] coseBytes = es256CoseKey(pub);
    CoseKey key = CoseKey.parse(coseBytes);
    assertThat(key.algorithm()).isEqualTo(-7L);

    byte[] message = "fido2-core".getBytes();
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(pair.getPrivate());
    signer.update(message);
    byte[] sig = signer.sign();

    assertThat(CoseSignatureVerifier.verify(key, message, sig)).isTrue();
    assertThat(CoseSignatureVerifier.verify(key, "tampered".getBytes(), sig)).isFalse();
  }

  @Test
  void parses_rs256_key_and_verifies_signature() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048, new SecureRandom());
    KeyPair pair = gen.generateKeyPair();
    java.security.interfaces.RSAPublicKey pub =
        (java.security.interfaces.RSAPublicKey) pair.getPublic();

    byte[] coseBytes = rs256CoseKey(pub);
    CoseKey key = CoseKey.parse(coseBytes);
    assertThat(key.algorithm()).isEqualTo(-257L);

    byte[] message = "fido2-core".getBytes();
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(pair.getPrivate());
    signer.update(message);
    byte[] sig = signer.sign();

    assertThat(CoseSignatureVerifier.verify(key, message, sig)).isTrue();
  }

  @Test
  void rejects_unsupported_algorithm() {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 1L); // kty: OKP
    m.put(3L, -8L); // alg: EdDSA — Milestone A 범위 밖
    byte[] cbor = com.crosscert.passkey.unit.fido2.CborTestEncoder.encodeMap(m);
    assertThatThrownBy(() -> CoseKey.parse(cbor)).isInstanceOf(CoseException.class);
  }

  // COSE_Key for EC2/ES256: {1:2, 3:-7, -1:1, -2:x, -3:y}
  private static byte[] es256CoseKey(ECPublicKey pub) {
    byte[] x = unsignedFixed(pub.getW().getAffineX(), 32);
    byte[] y = unsignedFixed(pub.getW().getAffineY(), 32);
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L);
    m.put(3L, -7L);
    m.put(-1L, 1L);
    m.put(-2L, x);
    m.put(-3L, y);
    return com.crosscert.passkey.unit.fido2.CborTestEncoder.encodeMap(m);
  }

  // COSE_Key for RSA/RS256: {1:3, 3:-257, -1:n, -2:e}
  private static byte[] rs256CoseKey(java.security.interfaces.RSAPublicKey pub) {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 3L);
    m.put(3L, -257L);
    m.put(-1L, toUnsigned(pub.getModulus()));
    m.put(-2L, toUnsigned(pub.getPublicExponent()));
    return com.crosscert.passkey.unit.fido2.CborTestEncoder.encodeMap(m);
  }

  private static byte[] unsignedFixed(java.math.BigInteger v, int len) {
    byte[] raw = toUnsigned(v);
    if (raw.length == len) {
      return raw;
    }
    byte[] out = new byte[len];
    System.arraycopy(raw, Math.max(0, raw.length - len), out,
        Math.max(0, len - raw.length), Math.min(raw.length, len));
    return out;
  }

  private static byte[] toUnsigned(java.math.BigInteger v) {
    byte[] raw = v.toByteArray();
    if (raw.length > 1 && raw[0] == 0) {
      byte[] trimmed = new byte[raw.length - 1];
      System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
      return trimmed;
    }
    return raw;
  }
}
```

- [ ] **Step 2: CBOR 테스트 인코더 헬퍼 작성**

테스트만을 위한 최소 CBOR 인코더. `server/src/test/java/com/crosscert/passkey/unit/fido2/CborTestEncoder.java`:

```java
package com.crosscert.passkey.unit.fido2;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR encoder — test-only. Production code never encodes CBOR (the server only decodes
 * authenticator output), so this lives under src/test and exists purely to build fixtures for the
 * {@code fido2} decoder/verifier tests.
 */
public final class CborTestEncoder {

  private CborTestEncoder() {}

  public static byte[] encodeMap(Map<Object, Object> map) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTypeAndLength(out, 5, map.size());
    for (Map.Entry<Object, Object> e : map.entrySet()) {
      writeItem(out, e.getKey());
      writeItem(out, e.getValue());
    }
    return out.toByteArray();
  }

  public static byte[] encode(Object value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeItem(out, value);
    return out.toByteArray();
  }

  private static void writeItem(ByteArrayOutputStream out, Object value) {
    if (value instanceof Long l) {
      if (l >= 0) {
        writeTypeAndLength(out, 0, l);
      } else {
        writeTypeAndLength(out, 1, -1 - l);
      }
    } else if (value instanceof Integer i) {
      writeItem(out, (long) i);
    } else if (value instanceof byte[] b) {
      writeTypeAndLength(out, 2, b.length);
      out.write(b, 0, b.length);
    } else if (value instanceof String s) {
      byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
      writeTypeAndLength(out, 3, utf8.length);
      out.write(utf8, 0, utf8.length);
    } else if (value instanceof List<?> list) {
      writeTypeAndLength(out, 4, list.size());
      for (Object item : list) {
        writeItem(out, item);
      }
    } else if (value instanceof Map<?, ?> m) {
      writeTypeAndLength(out, 5, m.size());
      for (Map.Entry<?, ?> e : m.entrySet()) {
        writeItem(out, e.getKey());
        writeItem(out, e.getValue());
      }
    } else if (value instanceof Boolean bool) {
      out.write(0xe0 | (bool ? 21 : 20));
    } else if (value == null) {
      out.write(0xf6);
    } else {
      throw new IllegalArgumentException("unsupported test CBOR value: " + value);
    }
  }

  private static void writeTypeAndLength(ByteArrayOutputStream out, int majorType, long len) {
    int mt = majorType << 5;
    if (len < 24) {
      out.write(mt | (int) len);
    } else if (len < 256) {
      out.write(mt | 24);
      out.write((int) len);
    } else if (len < 65536) {
      out.write(mt | 25);
      out.write((int) (len >> 8));
      out.write((int) (len & 0xff));
    } else {
      out.write(mt | 26);
      out.write((int) (len >> 24));
      out.write((int) (len >> 16) & 0xff);
      out.write((int) (len >> 8) & 0xff);
      out.write((int) (len & 0xff));
    }
  }
}
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.cose.CoseKeyTest"`
Expected: 컴파일 실패 — `CoseKey`, `CoseSignatureVerifier`, `CoseException` 미존재.

- [ ] **Step 4: `CoseException` 구현**

```java
package com.crosscert.passkey.fido2.cose;

/**
 * Thrown when a COSE_Key cannot be parsed or uses an algorithm outside the supported set
 * (ES256 / RS256 for Milestone A). Unchecked — translated to {@code UNSUPPORTED_ALGORITHM} or
 * {@code MALFORMED_CBOR} by the verifier layer.
 */
public class CoseException extends RuntimeException {
  public CoseException(String message) {
    super(message);
  }

  public CoseException(String message, Throwable cause) {
    super(message, cause);
  }
}
```

- [ ] **Step 5: `CoseKey` 구현**

```java
package com.crosscert.passkey.fido2.cose;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;

/**
 * A COSE_Key (RFC 8152) decoded into a JCA {@link PublicKey}. Only the two algorithms registered
 * in the WebAuthn registration options are supported in Milestone A:
 *
 * <ul>
 *   <li>ES256 (alg -7): EC2 key on the P-256 curve.
 *   <li>RS256 (alg -257): RSA key.
 * </ul>
 *
 * <p>The COSE label constants follow RFC 8152 §7: 1=kty, 3=alg; for EC2 -1=crv, -2=x, -3=y; for
 * RSA -1=n, -2=e.
 */
public final class CoseKey {

  private static final long LABEL_KTY = 1;
  private static final long LABEL_ALG = 3;
  private static final long KTY_EC2 = 2;
  private static final long KTY_RSA = 3;
  private static final long ALG_ES256 = -7;
  private static final long ALG_RS256 = -257;
  private static final long CRV_P256 = 1;

  private final long algorithm;
  private final PublicKey publicKey;

  private CoseKey(long algorithm, PublicKey publicKey) {
    this.algorithm = algorithm;
    this.publicKey = publicKey;
  }

  public long algorithm() {
    return algorithm;
  }

  public PublicKey publicKey() {
    return publicKey;
  }

  /** Parse a COSE_Key from its raw CBOR encoding. */
  public static CoseKey parse(byte[] coseCbor) {
    Object decoded;
    try {
      decoded = CborDecoder.decode(coseCbor);
    } catch (CborDecodeException e) {
      throw new CoseException("COSE_Key is not valid CBOR", e);
    }
    if (!(decoded instanceof Map<?, ?> map)) {
      throw new CoseException("COSE_Key is not a CBOR map");
    }
    long kty = asLong(map.get(LABEL_KTY), "kty");
    long alg = asLong(map.get(LABEL_ALG), "alg");
    if (kty == KTY_EC2 && alg == ALG_ES256) {
      return new CoseKey(alg, parseEc2(map));
    }
    if (kty == KTY_RSA && alg == ALG_RS256) {
      return new CoseKey(alg, parseRsa(map));
    }
    throw new CoseException("unsupported COSE key: kty=" + kty + " alg=" + alg);
  }

  private static PublicKey parseEc2(Map<?, ?> map) {
    long crv = asLong(map.get(-1L), "crv");
    if (crv != CRV_P256) {
      throw new CoseException("unsupported EC curve: " + crv);
    }
    BigInteger x = new BigInteger(1, asBytes(map.get(-2L), "x"));
    BigInteger y = new BigInteger(1, asBytes(map.get(-3L), "y"));
    try {
      java.security.AlgorithmParameters params =
          java.security.AlgorithmParameters.getInstance("EC");
      params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
      ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(x, y), ecSpec);
      return KeyFactory.getInstance("EC").generatePublic(spec);
    } catch (Exception e) {
      throw new CoseException("failed to build EC public key", e);
    }
  }

  private static PublicKey parseRsa(Map<?, ?> map) {
    BigInteger n = new BigInteger(1, asBytes(map.get(-1L), "n"));
    BigInteger e = new BigInteger(1, asBytes(map.get(-2L), "e"));
    try {
      return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    } catch (Exception ex) {
      throw new CoseException("failed to build RSA public key", ex);
    }
  }

  private static long asLong(Object value, String label) {
    if (value instanceof Long l) {
      return l;
    }
    throw new CoseException("COSE_Key field '" + label + "' missing or not an integer");
  }

  private static byte[] asBytes(Object value, String label) {
    if (value instanceof byte[] b) {
      return b;
    }
    throw new CoseException("COSE_Key field '" + label + "' missing or not a byte string");
  }
}
```

- [ ] **Step 6: `CoseSignatureVerifier` 구현**

```java
package com.crosscert.passkey.fido2.cose;

import java.security.GeneralSecurityException;
import java.security.Signature;

/**
 * Verifies a signature produced by an authenticator's credential private key against the COSE
 * public key recorded at registration. ES256 signatures arrive as ASN.1 DER-encoded ECDSA values;
 * the JCA {@code SHA256withECDSA} signer consumes that form directly, so no manual DER unwrapping
 * is required.
 */
public final class CoseSignatureVerifier {

  private CoseSignatureVerifier() {}

  /** Returns {@code true} when {@code signature} is a valid signature of {@code signedData}. */
  public static boolean verify(CoseKey key, byte[] signedData, byte[] signature) {
    String jcaAlgorithm = jcaAlgorithm(key.algorithm());
    try {
      Signature verifier = Signature.getInstance(jcaAlgorithm);
      verifier.initVerify(key.publicKey());
      verifier.update(signedData);
      return verifier.verify(signature);
    } catch (GeneralSecurityException e) {
      // A malformed signature (bad DER, wrong length) surfaces here — treat as a failed
      // verification rather than an error, the caller maps it to SIGNATURE_INVALID.
      return false;
    }
  }

  private static String jcaAlgorithm(long coseAlg) {
    return switch ((int) coseAlg) {
      case -7 -> "SHA256withECDSA";
      case -257 -> "SHA256withRSA";
      default -> throw new CoseException("unsupported COSE algorithm: " + coseAlg);
    };
  }
}
```

- [ ] **Step 7: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.cose.CoseKeyTest"`
Expected: PASS (3 tests).

- [ ] **Step 8: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/cose/ server/src/test/java/com/crosscert/passkey/unit/fido2/
git commit -m "feat(fido2): COSE 키 디코딩 + ES256/RS256 서명 검증 추가"
```

---

### Task 3: model 레코드 — Flags / AuthenticatorData / AttestedCredentialData

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/model/Flags.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/model/AttestedCredentialData.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/model/AuthenticatorData.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/model/AuthenticatorDataTest.java`

`AttestedCredentialData.parse(byte[])`는 DB의 `credential.public_key_cose`(webauthn4j `AttestedCredentialDataConverter` 직렬화 형식)를 그대로 읽는다. 이 형식은 WebAuthn authData의 attestedCredentialData 구조(AAGUID 16B + credIdLen 2B + credId + COSE key) 그 자체다 — 별도 마이그레이션 불필요.

- [ ] **Step 1: 실패 테스트 작성**

`AuthenticatorDataTest.java`:

```java
package com.crosscert.passkey.unit.fido2.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.model.AuthenticatorData;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthenticatorDataTest {

  @Test
  void parses_authenticator_data_without_attested_credential() {
    // rpIdHash(32) + flags(1, UP only) + signCount(4) — no AT bit.
    byte[] rpIdHash = new byte[32];
    java.util.Arrays.fill(rpIdHash, (byte) 0xab);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(rpIdHash);
    out.write(0x01); // UP
    out.writeBytes(new byte[] {0, 0, 0, 5}); // signCount = 5

    AuthenticatorData ad = AuthenticatorData.parse(out.toByteArray());
    assertThat(ad.rpIdHash()).containsExactly(rpIdHash);
    assertThat(ad.flags().userPresent()).isTrue();
    assertThat(ad.flags().userVerified()).isFalse();
    assertThat(ad.flags().attestedCredentialDataIncluded()).isFalse();
    assertThat(ad.signCount()).isEqualTo(5L);
    assertThat(ad.attestedCredentialData()).isNull();
  }

  @Test
  void parses_authenticator_data_with_attested_credential() {
    byte[] coseKey = sampleCoseKey();
    byte[] aaguid = new byte[16];
    java.util.Arrays.fill(aaguid, (byte) 0x11);
    byte[] credId = new byte[] {1, 2, 3, 4};

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(new byte[32]); // rpIdHash
    out.write(0x45); // UP(0x01) | UV(0x04) | AT(0x40)
    out.writeBytes(new byte[] {0, 0, 0, 0}); // signCount
    out.writeBytes(aaguid);
    out.writeBytes(new byte[] {0, 4}); // credentialId length = 4
    out.writeBytes(credId);
    out.writeBytes(coseKey);

    AuthenticatorData ad = AuthenticatorData.parse(out.toByteArray());
    assertThat(ad.flags().attestedCredentialDataIncluded()).isTrue();
    AttestedCredentialData acd = ad.attestedCredentialData();
    assertThat(acd.credentialId()).containsExactly(credId);
    assertThat(acd.aaguid()).containsExactly(aaguid);
    assertThat(acd.coseKey().algorithm()).isEqualTo(-7L);
  }

  @Test
  void attested_credential_data_round_trips_webauthn4j_serialized_form() {
    // webauthn4j AttestedCredentialDataConverter format: aaguid(16) + credIdLen(2) + credId + cose
    byte[] aaguid = new byte[16];
    byte[] credId = new byte[] {9, 8, 7};
    byte[] coseKey = sampleCoseKey();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(aaguid);
    out.writeBytes(new byte[] {0, 3});
    out.writeBytes(credId);
    out.writeBytes(coseKey);

    AttestedCredentialData acd = AttestedCredentialData.parse(out.toByteArray());
    assertThat(acd.credentialId()).containsExactly(credId);
    assertThat(acd.coseKey().algorithm()).isEqualTo(-7L);
  }

  @Test
  void rejects_truncated_authenticator_data() {
    assertThatThrownBy(() -> AuthenticatorData.parse(new byte[10]))
        .isInstanceOf(CborDecodeException.class);
  }

  private static byte[] sampleCoseKey() {
    // A structurally valid ES256 COSE_Key with zero-coordinate points — parsing only.
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L);
    m.put(3L, -7L);
    m.put(-1L, 1L);
    m.put(-2L, new byte[32]);
    m.put(-3L, new byte[32]);
    return CborTestEncoder.encodeMap(m);
  }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.model.AuthenticatorDataTest"`
Expected: 컴파일 실패 — `Flags`, `AuthenticatorData`, `AttestedCredentialData` 미존재.

- [ ] **Step 3: `Flags` 구현**

```java
package com.crosscert.passkey.fido2.model;

/**
 * The authenticator data flags byte (WebAuthn L3 §6.1). Each bit is a boolean signal the verifier
 * checks: UP and UV gate user presence/verification, AT signals an embedded attested credential,
 * ED signals extension data, and BE/BS carry CTAP 2.1 backup eligibility / state.
 */
public record Flags(
    boolean userPresent,
    boolean userVerified,
    boolean backupEligible,
    boolean backupState,
    boolean attestedCredentialDataIncluded,
    boolean extensionDataIncluded) {

  /** Decode the single flags byte from authenticator data. */
  public static Flags from(byte b) {
    int v = b & 0xff;
    return new Flags(
        (v & 0x01) != 0, // UP — bit 0
        (v & 0x04) != 0, // UV — bit 2
        (v & 0x08) != 0, // BE — bit 3
        (v & 0x10) != 0, // BS — bit 4
        (v & 0x40) != 0, // AT — bit 6
        (v & 0x80) != 0); // ED — bit 7
  }
}
```

- [ ] **Step 4: `AttestedCredentialData` 구현**

```java
package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import com.crosscert.passkey.fido2.cose.CoseKey;
import java.util.Arrays;

/**
 * The attested credential data embedded in authenticator data when the AT flag is set (WebAuthn
 * L3 §6.5.1): the authenticator AAGUID, the new credential id, and the credential public key as a
 * COSE_Key.
 *
 * <p>The byte layout — {@code aaguid(16) || credentialIdLength(2, big-endian) || credentialId ||
 * coseKey} — is identical to the form webauthn4j's {@code AttestedCredentialDataConverter} writes
 * into our {@code credential.public_key_cose} column, so {@link #parse(byte[])} reads existing
 * stored credentials without any migration.
 */
public record AttestedCredentialData(byte[] aaguid, byte[] credentialId, byte[] coseKeyBytes) {

  /** The credential public key parsed from {@link #coseKeyBytes()}. */
  public CoseKey coseKey() {
    return CoseKey.parse(coseKeyBytes);
  }

  /**
   * Parse attested credential data from a byte array whose entire remaining content after the
   * fixed header is a single COSE_Key. Used for the standalone {@code credential.public_key_cose}
   * column.
   */
  public static AttestedCredentialData parse(byte[] data) {
    Parsed p = parseWithLength(data, 0);
    return p.value();
  }

  /**
   * Parse attested credential data starting at {@code offset} within a larger buffer (the
   * authenticator data case, where extension data may follow). Reports the end offset so the
   * caller can continue parsing.
   */
  public static Parsed parseWithLength(byte[] data, int offset) {
    if (data.length < offset + 18) {
      throw new CborDecodeException("attested credential data truncated");
    }
    byte[] aaguid = Arrays.copyOfRange(data, offset, offset + 16);
    int credIdLen = ((data[offset + 16] & 0xff) << 8) | (data[offset + 17] & 0xff);
    int credIdEnd = offset + 18 + credIdLen;
    if (data.length < credIdEnd) {
      throw new CborDecodeException("attested credential data credentialId truncated");
    }
    byte[] credentialId = Arrays.copyOfRange(data, offset + 18, credIdEnd);
    // The COSE_Key is the next CBOR item; decodeWithLength tells us where it ends.
    byte[] rest = Arrays.copyOfRange(data, credIdEnd, data.length);
    CborDecoder.DecodeResult cose = CborDecoder.decodeWithLength(rest);
    byte[] coseBytes = Arrays.copyOfRange(rest, 0, cose.consumed());
    return new Parsed(
        new AttestedCredentialData(aaguid, credentialId, coseBytes), credIdEnd + cose.consumed());
  }

  /** An {@link AttestedCredentialData} paired with the offset where parsing finished. */
  public record Parsed(AttestedCredentialData value, int endOffset) {}
}
```

- [ ] **Step 5: `AuthenticatorData` 구현**

```java
package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import java.util.Arrays;

/**
 * Parsed WebAuthn authenticator data (WebAuthn L3 §6.1): the SHA-256 of the RP id, the {@link
 * Flags} byte, a 32-bit signature counter, and — when the AT flag is set — the embedded {@link
 * AttestedCredentialData}. Extension data, when present, is not interpreted in Milestone A.
 */
public record AuthenticatorData(
    byte[] rpIdHash,
    Flags flags,
    long signCount,
    AttestedCredentialData attestedCredentialData,
    byte[] rawBytes) {

  private static final int HEADER_LENGTH = 37; // rpIdHash(32) + flags(1) + signCount(4)

  /** Parse authenticator data from its raw byte form. */
  public static AuthenticatorData parse(byte[] data) {
    if (data.length < HEADER_LENGTH) {
      throw new CborDecodeException("authenticator data shorter than 37-byte header");
    }
    byte[] rpIdHash = Arrays.copyOfRange(data, 0, 32);
    Flags flags = Flags.from(data[32]);
    long signCount =
        ((data[33] & 0xffL) << 24)
            | ((data[34] & 0xffL) << 16)
            | ((data[35] & 0xffL) << 8)
            | (data[36] & 0xffL);
    AttestedCredentialData acd = null;
    if (flags.attestedCredentialDataIncluded()) {
      acd = AttestedCredentialData.parseWithLength(data, HEADER_LENGTH).value();
    }
    return new AuthenticatorData(rpIdHash, flags, signCount, acd, data);
  }
}
```

- [ ] **Step 6: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.model.AuthenticatorDataTest"`
Expected: PASS (4 tests).

- [ ] **Step 7: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/model/ server/src/test/java/com/crosscert/passkey/unit/fido2/model/
git commit -m "feat(fido2): AuthenticatorData / AttestedCredentialData 모델 파서 추가"
```

---

### Task 4: model 레코드 — CollectedClientData / AttestationObject

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/model/CollectedClientData.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/model/AttestationObject.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/model/CollectedClientDataTest.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/model/AttestationObjectTest.java`

- [ ] **Step 1: `CollectedClientDataTest` 작성**

```java
package com.crosscert.passkey.unit.fido2.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.model.CollectedClientData;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CollectedClientDataTest {

  @Test
  void parses_client_data_json() {
    String json =
        "{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\","
            + "\"origin\":\"https://example.com\",\"crossOrigin\":false}";
    CollectedClientData cd = CollectedClientData.parse(json.getBytes(StandardCharsets.UTF_8));
    assertThat(cd.type()).isEqualTo("webauthn.create");
    assertThat(cd.challenge()).isEqualTo("Y2hhbGxlbmdl");
    assertThat(cd.origin()).isEqualTo("https://example.com");
    assertThat(cd.crossOrigin()).isFalse();
  }

  @Test
  void tolerates_missing_cross_origin() {
    String json =
        "{\"type\":\"webauthn.get\",\"challenge\":\"YWJj\",\"origin\":\"https://a.com\"}";
    CollectedClientData cd = CollectedClientData.parse(json.getBytes(StandardCharsets.UTF_8));
    assertThat(cd.crossOrigin()).isFalse();
  }

  @Test
  void rejects_malformed_json() {
    assertThatThrownBy(() -> CollectedClientData.parse("not json".getBytes()))
        .isInstanceOf(CborDecodeException.class);
  }
}
```

- [ ] **Step 2: `AttestationObjectTest` 작성**

```java
package com.crosscert.passkey.unit.fido2.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AttestationObjectTest {

  @Test
  void parses_none_attestation_object() {
    byte[] authData = sampleAuthData();
    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", "none");
    obj.put("attStmt", new LinkedHashMap<>());
    obj.put("authData", authData);

    AttestationObject parsed = AttestationObject.parse(CborTestEncoder.encodeMap(obj));
    assertThat(parsed.format()).isEqualTo("none");
    assertThat(parsed.attestationStatement()).isEmpty();
    assertThat(parsed.authenticatorData().rpIdHash()).hasSize(32);
  }

  private static byte[] sampleAuthData() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(new byte[32]); // rpIdHash
    out.write(0x01); // UP
    out.writeBytes(new byte[] {0, 0, 0, 1}); // signCount
    return out.toByteArray();
  }
}
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.model.CollectedClientDataTest" --tests "com.crosscert.passkey.unit.fido2.model.AttestationObjectTest"`
Expected: 컴파일 실패 — `CollectedClientData`, `AttestationObject` 미존재.

- [ ] **Step 4: `CollectedClientData` 구현**

clientDataJSON은 JSON이므로 Spring Boot에 이미 있는 Jackson을 쓴다. `fido2`는 Spring을 import하지 않지만 `com.fasterxml.jackson`은 라이브러리이므로 경계 규칙(§3, Spring·도메인 금지)에 위배되지 않는다.

```java
package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The client data collected by the browser for a ceremony (WebAuthn L3 §5.8.1), parsed from
 * clientDataJSON. The verifier checks {@link #type()}, {@link #challenge()} and {@link #origin()}
 * against the values the server expects.
 */
public record CollectedClientData(
    String type, String challenge, String origin, boolean crossOrigin) {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** Parse clientDataJSON (UTF-8 encoded JSON). */
  public static CollectedClientData parse(byte[] clientDataJson) {
    try {
      JsonNode node = MAPPER.readTree(clientDataJson);
      JsonNode type = node.get("type");
      JsonNode challenge = node.get("challenge");
      JsonNode origin = node.get("origin");
      if (type == null || challenge == null || origin == null) {
        throw new CborDecodeException("clientDataJSON missing a required field");
      }
      JsonNode crossOrigin = node.get("crossOrigin");
      return new CollectedClientData(
          type.asText(),
          challenge.asText(),
          origin.asText(),
          crossOrigin != null && crossOrigin.asBoolean(false));
    } catch (CborDecodeException e) {
      throw e;
    } catch (Exception e) {
      throw new CborDecodeException("clientDataJSON is not valid JSON");
    }
  }
}
```

- [ ] **Step 5: `AttestationObject` 구현**

```java
package com.crosscert.passkey.fido2.model;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import java.util.Map;

/**
 * The attestation object returned by {@code navigator.credentials.create()} (WebAuthn L3 §6.5):
 * a CBOR map of the attestation statement format, the format-specific attestation statement, and
 * the authenticator data.
 */
public record AttestationObject(
    String format, Map<?, ?> attestationStatement, AuthenticatorData authenticatorData) {

  /** Parse an attestation object from its raw CBOR encoding. */
  public static AttestationObject parse(byte[] cbor) {
    Object decoded = CborDecoder.decode(cbor);
    if (!(decoded instanceof Map<?, ?> map)) {
      throw new CborDecodeException("attestationObject is not a CBOR map");
    }
    Object fmt = map.get("fmt");
    Object attStmt = map.get("attStmt");
    Object authData = map.get("authData");
    if (!(fmt instanceof String fmtStr)) {
      throw new CborDecodeException("attestationObject.fmt missing or not a string");
    }
    if (!(attStmt instanceof Map<?, ?> attStmtMap)) {
      throw new CborDecodeException("attestationObject.attStmt missing or not a map");
    }
    if (!(authData instanceof byte[] authDataBytes)) {
      throw new CborDecodeException("attestationObject.authData missing or not a byte string");
    }
    return new AttestationObject(fmtStr, attStmtMap, AuthenticatorData.parse(authDataBytes));
  }
}
```

- [ ] **Step 6: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.model.CollectedClientDataTest" --tests "com.crosscert.passkey.unit.fido2.model.AttestationObjectTest"`
Expected: PASS (4 tests).

- [ ] **Step 7: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/model/ server/src/test/java/com/crosscert/passkey/unit/fido2/model/
git commit -m "feat(fido2): CollectedClientData / AttestationObject 모델 파서 추가"
```

---

### Task 5: `Fido2VerificationException` + ArchUnit 경계 룰

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java`
- Modify: `server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java`

- [ ] **Step 1: `Fido2VerificationException` 구현**

```java
package com.crosscert.passkey.fido2;

/**
 * The single checked exception the {@code fido2} core throws when a registration or authentication
 * ceremony fails verification. It carries a {@link FailureReason} so the calling domain service
 * can log a precise cause and map to the right {@code ErrorCode} — the core itself never depends
 * on the application's {@code BusinessException} / {@code ErrorCode} types (enforced by ArchUnit).
 */
public class Fido2VerificationException extends Exception {

  /** The specific verification step that failed. */
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
    ATTESTATION_INVALID,
    SIGNATURE_INVALID
  }

  private final FailureReason reason;

  public Fido2VerificationException(FailureReason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public FailureReason reason() {
    return reason;
  }
}
```

- [ ] **Step 2: ArchUnit 룰 추가 — 실패 테스트**

`PackageArchitectureTest.java`의 클래스 본문 끝(마지막 `}` 직전, `admin_tenant_controllers_depend_on_admin_authz` 뒤)에 추가:

```java
  // Rule 7: the fido2 core is a pure WebAuthn implementation — it must not depend on any domain
  // package, on Spring, or on the application's exception types. Only java.* + the fido2 package
  // itself + Jackson (clientDataJSON parsing) are permitted.
  @Test
  void fido2_core_is_pure() {
    noClasses()
        .that()
        .resideInAPackage("..fido2..")
        .should()
        .dependOnClassesThat()
        .resideInAnyPackage(
            "..tenant..",
            "..auth..",
            "..credential..",
            "..audit..",
            "..admin..",
            "..common..",
            "..infrastructure..",
            "..ratelimit..",
            "org.springframework..")
        .check(CLASSES);
  }
```

- [ ] **Step 3: 테스트 실행 — 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.architecture.PackageArchitectureTest"`
Expected: PASS (7 tests). 현재 `fido2` 패키지는 순수하므로 Rule 7도 통과한다. 통과하지 않으면 위반 클래스를 수정한다.

- [ ] **Step 4: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/Fido2VerificationException.java server/src/test/java/com/crosscert/passkey/architecture/PackageArchitectureTest.java
git commit -m "feat(fido2): Fido2VerificationException + fido2 순수성 ArchUnit 룰 추가"
```

---

## Phase 1 — 인증(assertion) 경로 교체

webauthn4j는 등록 경로에서 계속 사용한다. 인증 경로만 자체 코어로 교체하고, 차등 테스트로 두 구현의 결과 일치를 확인한다.

### Task 6: `AuthenticationVerifier` 구현

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/AuthenticationVerificationRequest.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/AuthenticationVerificationResult.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/AuthenticationVerifier.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/AuthenticationVerifierTest.java`

- [ ] **Step 1: 입력/출력 레코드 작성**

`AuthenticationVerificationRequest.java`:

```java
package com.crosscert.passkey.fido2;

import java.util.List;

/**
 * Inputs for verifying a {@code navigator.credentials.get()} assertion. All byte arrays are the
 * raw (already base64url-decoded) values; {@code expectedChallenge} is the raw challenge bytes the
 * server issued. {@code storedCoseKeyBytes} is the credential public key recorded at registration
 * — for this server, the {@code credential.public_key_cose} column.
 */
public record AuthenticationVerificationRequest(
    byte[] authenticatorData,
    byte[] clientDataJson,
    byte[] signature,
    byte[] expectedChallenge,
    List<String> expectedOrigins,
    String expectedRpId,
    byte[] storedCoseKeyBytes,
    boolean userVerificationRequired) {}
```

`AuthenticationVerificationResult.java`:

```java
package com.crosscert.passkey.fido2;

/**
 * Verified facts extracted from a successful assertion. The caller applies its own policy:
 * {@code newSignCount} feeds the existing {@code Credential.updateSignatureCounter()} clone
 * detection, and {@code backupState} drives the {@code CREDENTIAL_BACKUP_STATE_CHANGED} audit.
 */
public record AuthenticationVerificationResult(
    long newSignCount, boolean userVerified, boolean backupEligible, boolean backupState) {}
```

- [ ] **Step 2: `AuthenticationVerifierTest` 작성**

```java
package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthenticationVerifierTest {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  @Test
  void verifies_a_valid_assertion() throws Exception {
    Fixture f = new Fixture("https://example.com", "example.com", true, true);
    AuthenticationVerificationResult result =
        new AuthenticationVerifier().verify(f.request(true));
    assertThat(result.newSignCount()).isEqualTo(7L);
    assertThat(result.userVerified()).isTrue();
  }

  @Test
  void rejects_challenge_mismatch() throws Exception {
    Fixture f = new Fixture("https://example.com", "example.com", true, true);
    AuthenticationVerificationRequest req = f.requestWithChallenge("d3JvbmctY2hhbGxlbmdl".getBytes());
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.CHALLENGE_MISMATCH);
  }

  @Test
  void rejects_origin_mismatch() throws Exception {
    Fixture f = new Fixture("https://evil.com", "example.com", true, true);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(f.request(true)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ORIGIN_MISMATCH);
  }

  @Test
  void rejects_missing_uv_when_required() throws Exception {
    Fixture f = new Fixture("https://example.com", "example.com", true, false);
    AuthenticationVerificationRequest req = f.requestUvRequired();
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UV_FLAG_REQUIRED);
  }

  @Test
  void rejects_bad_signature() throws Exception {
    Fixture f = new Fixture("https://example.com", "example.com", true, true);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(f.request(false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.SIGNATURE_INVALID);
  }

  /** Builds a self-consistent assertion: real EC key, real signature over authData||clientHash. */
  private static final class Fixture {
    final KeyPair keyPair;
    final byte[] coseKey;
    final byte[] authData;
    final byte[] clientDataJson;
    final byte[] challenge = "Y2hhbGxlbmdl".getBytes();
    final String rpId;

    Fixture(String origin, String rpId, boolean up, boolean uv) throws Exception {
      this.rpId = rpId;
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec("secp256r1"));
      this.keyPair = gen.generateKeyPair();
      this.coseKey = es256CoseKey((ECPublicKey) keyPair.getPublic());

      byte[] rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.getBytes());
      ByteArrayOutputStream ad = new ByteArrayOutputStream();
      ad.writeBytes(rpIdHash);
      int flags = (up ? 0x01 : 0) | (uv ? 0x04 : 0);
      ad.write(flags);
      ad.writeBytes(new byte[] {0, 0, 0, 7}); // signCount = 7
      this.authData = ad.toByteArray();

      String json =
          "{\"type\":\"webauthn.get\",\"challenge\":\""
              + B64URL.encodeToString(challenge)
              + "\",\"origin\":\""
              + origin
              + "\"}";
      this.clientDataJson = json.getBytes(StandardCharsets.UTF_8);
    }

    AuthenticationVerificationRequest request(boolean validSignature) throws Exception {
      return build(challenge, false, validSignature);
    }

    AuthenticationVerificationRequest requestWithChallenge(byte[] expected) throws Exception {
      return new AuthenticationVerificationRequest(
          authData, clientDataJson, sign(true), expected, List.of("https://example.com"),
          rpId, coseKey, false);
    }

    AuthenticationVerificationRequest requestUvRequired() throws Exception {
      return build(challenge, true, true);
    }

    private AuthenticationVerificationRequest build(
        byte[] expectedChallenge, boolean uvRequired, boolean validSignature) throws Exception {
      return new AuthenticationVerificationRequest(
          authData, clientDataJson, sign(validSignature), expectedChallenge,
          List.of("https://example.com"), rpId, coseKey, uvRequired);
    }

    private byte[] sign(boolean valid) throws Exception {
      byte[] clientHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
      ByteArrayOutputStream signed = new ByteArrayOutputStream();
      signed.writeBytes(authData);
      signed.writeBytes(clientHash);
      Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(keyPair.getPrivate());
      signer.update(valid ? signed.toByteArray() : "garbage".getBytes());
      return signer.sign();
    }

    private static byte[] es256CoseKey(ECPublicKey pub) {
      Map<Object, Object> m = new LinkedHashMap<>();
      m.put(1L, 2L);
      m.put(3L, -7L);
      m.put(-1L, 1L);
      m.put(-2L, fixed(pub.getW().getAffineX()));
      m.put(-3L, fixed(pub.getW().getAffineY()));
      return CborTestEncoder.encodeMap(m);
    }

    private static byte[] fixed(java.math.BigInteger v) {
      byte[] raw = v.toByteArray();
      byte[] out = new byte[32];
      if (raw.length > 32) {
        System.arraycopy(raw, raw.length - 32, out, 0, 32);
      } else {
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
      }
      return out;
    }
  }
}
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.AuthenticationVerifierTest"`
Expected: 컴파일 실패 — `AuthenticationVerifier` 미존재.

- [ ] **Step 4: `AuthenticationVerifier` 구현**

```java
package com.crosscert.passkey.fido2;

import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.model.AuthenticatorData;
import com.crosscert.passkey.fido2.model.CollectedClientData;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Verifies a {@code navigator.credentials.get()} assertion against the WebAuthn L3 §7.2 algorithm:
 * client data type / challenge / origin, the RP id hash, the user-presence and user-verification
 * flags, and the credential signature. On success it returns the verified facts; it never applies
 * tenant policy (AAGUID allow-lists, signature-counter regression) — that stays with the caller.
 */
public final class AuthenticationVerifier {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

  /** Verify the assertion described by {@code req}, or throw {@link Fido2VerificationException}. */
  public AuthenticationVerificationResult verify(AuthenticationVerificationRequest req)
      throws Fido2VerificationException {
    CollectedClientData clientData = parseClientData(req.clientDataJson());

    if (!"webauthn.get".equals(clientData.type())) {
      throw new Fido2VerificationException(
          FailureReason.WRONG_CEREMONY_TYPE, "clientData.type is not webauthn.get");
    }
    if (!constantTimeEquals(
        decodeB64Url(clientData.challenge()), req.expectedChallenge())) {
      throw new Fido2VerificationException(
          FailureReason.CHALLENGE_MISMATCH, "assertion challenge does not match");
    }
    if (!req.expectedOrigins().contains(clientData.origin())) {
      throw new Fido2VerificationException(
          FailureReason.ORIGIN_MISMATCH, "origin not allow-listed: " + clientData.origin());
    }

    AuthenticatorData authData = parseAuthData(req.authenticatorData());
    verifyRpIdHash(authData, req.expectedRpId());
    if (!authData.flags().userPresent()) {
      throw new Fido2VerificationException(
          FailureReason.UP_FLAG_MISSING, "user-presence flag not set");
    }
    if (req.userVerificationRequired() && !authData.flags().userVerified()) {
      throw new Fido2VerificationException(
          FailureReason.UV_FLAG_REQUIRED, "user-verification required but flag not set");
    }

    verifySignature(req, authData);

    return new AuthenticationVerificationResult(
        authData.signCount(),
        authData.flags().userVerified(),
        authData.flags().backupEligible(),
        authData.flags().backupState());
  }

  private void verifySignature(AuthenticationVerificationRequest req, AuthenticatorData authData)
      throws Fido2VerificationException {
    CoseKey key;
    try {
      // storedCoseKeyBytes is the webauthn4j AttestedCredentialData blob; pull the COSE key out.
      AttestedCredentialData stored = AttestedCredentialData.parse(req.storedCoseKeyBytes());
      key = stored.coseKey();
    } catch (CborDecodeException | CoseException e) {
      throw new Fido2VerificationException(
          FailureReason.UNSUPPORTED_ALGORITHM, "stored credential key unreadable: " + e.getMessage());
    }
    byte[] clientDataHash = sha256(req.clientDataJson());
    ByteArrayOutputStream signedData = new ByteArrayOutputStream();
    signedData.writeBytes(authData.rawBytes());
    signedData.writeBytes(clientDataHash);
    if (!CoseSignatureVerifier.verify(key, signedData.toByteArray(), req.signature())) {
      throw new Fido2VerificationException(
          FailureReason.SIGNATURE_INVALID, "assertion signature verification failed");
    }
  }

  private void verifyRpIdHash(AuthenticatorData authData, String rpId)
      throws Fido2VerificationException {
    byte[] expected = sha256(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    if (!constantTimeEquals(expected, authData.rpIdHash())) {
      throw new Fido2VerificationException(
          FailureReason.RPID_HASH_MISMATCH, "authenticator rpIdHash does not match RP id");
    }
  }

  private static CollectedClientData parseClientData(byte[] json)
      throws Fido2VerificationException {
    try {
      return CollectedClientData.parse(json);
    } catch (CborDecodeException e) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CLIENT_DATA, e.getMessage());
    }
  }

  private static AuthenticatorData parseAuthData(byte[] raw) throws Fido2VerificationException {
    try {
      return AuthenticatorData.parse(raw);
    } catch (CborDecodeException e) {
      throw new Fido2VerificationException(FailureReason.MALFORMED_CBOR, e.getMessage());
    }
  }

  private static byte[] decodeB64Url(String s) throws Fido2VerificationException {
    try {
      return B64URL.decode(s);
    } catch (IllegalArgumentException e) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CLIENT_DATA, "challenge is not valid base64url");
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static boolean constantTimeEquals(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }
}
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.AuthenticationVerifierTest"`
Expected: PASS (5 tests).

- [ ] **Step 6: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/Authentication*.java server/src/test/java/com/crosscert/passkey/unit/fido2/AuthenticationVerifierTest.java
git commit -m "feat(fido2): AuthenticationVerifier — assertion 검증 구현"
```

---

### Task 7: `AuthenticationService.verifyAssertion()` 교체

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/service/AuthenticationService.java`

`verifyAssertion()`만 자체 코어로 교체한다. webauthn4j import·필드·`verifyAssertion()` 메서드 바디를 바꾸고, 나머지(`beginAuthentication`, `finishAuthentication`, signCount 처리)는 손대지 않는다.

- [ ] **Step 1: webauthn4j 필드/생성자 의존 제거**

`AuthenticationService.java`에서 다음 필드 선언을 삭제:

```java
  private final WebAuthnManager webAuthnManager;
```
```java
  private final ObjectConverter objectConverter = new ObjectConverter();
  private final AttestedCredentialDataConverter attestedConverter =
      new AttestedCredentialDataConverter(objectConverter);
```

`@RequiredArgsConstructor`가 생성자를 만들므로 `webAuthnManager`를 필드에서 지우면 생성자 인자에서도 자동 제거된다.

- [ ] **Step 2: webauthn4j import 제거**

다음 import 라인을 모두 삭제:

```java
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import java.util.LinkedHashSet;
import java.util.Set;
```

다음 import를 추가:

```java
import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
import com.crosscert.passkey.fido2.Fido2VerificationException;
```

- [ ] **Step 3: `verifyAssertion()` 메서드 교체**

기존 `verifyAssertion(...)` 메서드 전체(시그니처는 `private AuthenticationData verifyAssertion(TenantWebauthnConfig cfg, ChallengeRecord stored, Credential credential, AuthenticationVerifyRequest req)`)를 아래로 교체. 반환 타입이 `AuthenticationData` → `AuthenticationVerificationResult`로 바뀐다:

```java
  private AuthenticationVerificationResult verifyAssertion(
      TenantWebauthnConfig cfg,
      ChallengeRecord stored,
      Credential credential,
      AuthenticationVerifyRequest req) {
    AuthenticationVerificationRequest verifyReq =
        new AuthenticationVerificationRequest(
            Base64UrlCodec.decode(req.authenticatorDataB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(req.signatureB64u()),
            Base64UrlCodec.decode(stored.challengeB64u()),
            cfg.originList(),
            cfg.getRpId(),
            credential.getPublicKeyCose(),
            cfg.getUserVerification().isStrictRequired());
    try {
      return new AuthenticationVerifier().verify(verifyReq);
    } catch (Fido2VerificationException e) {
      log.warn(
          "auth.assertion.invalid tenantId={} credentialId={} reason={} detail={}",
          cfg.getTenantId(),
          LogSanitiser.forLog(req.credentialId()),
          e.reason(),
          LogSanitiser.forLog(e.getMessage()));
      metrics.getAuthenticationFailure().increment();
      throw new BusinessException(ErrorCode.ASSERTION_INVALID, e.getMessage());
    }
  }
```

- [ ] **Step 4: `finishAuthentication()`의 호출부 조정**

`finishAuthentication()` 안의 이 라인:

```java
    AuthenticationData authnData = verifyAssertion(cfg, stored, credential, req);

    long newCounter = authnData.getAuthenticatorData().getSignCount();
```

를 아래로 교체:

```java
    AuthenticationVerificationResult authnResult = verifyAssertion(cfg, stored, credential, req);

    long newCounter = authnResult.newSignCount();
```

같은 메서드 안의 `authnData.getAuthenticatorData().isFlagBS()`를 사용하는 라인:

```java
    boolean newBackupState = authnData.getAuthenticatorData().isFlagBS();
```

를 아래로 교체:

```java
    boolean newBackupState = authnResult.backupState();
```

- [ ] **Step 5: 차등 테스트 작성 — webauthn4j vs 자체 코어**

`server/src/test/java/com/crosscert/passkey/unit/fido2/AssertionDifferentialTest.java` 생성. 동일한 인증기 출력 fixture를 webauthn4j와 자체 코어 양쪽에 넣어 `signCount`·`uv`·검증 성공/실패가 일치하는지 확인:

```java
package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Differential test — the same authenticator assertion is verified by both webauthn4j and the
 * self-implemented core, and the verified facts must agree. Acts as the safety net for Phase 1
 * until webauthn4j is removed in Phase 2. Uses {@code Fido2Fixtures} for a shared, self-consistent
 * assertion built from a real EC key (extract the {@code Fixture} from
 * {@code AuthenticationVerifierTest} into a shared helper, or duplicate the fixture builder here).
 */
class AssertionDifferentialTest {

  @Test
  void self_core_and_webauthn4j_agree_on_valid_assertion() throws Exception {
    Fido2Fixtures.Assertion a = Fido2Fixtures.validAssertion("https://example.com", "example.com");

    // Self core.
    AuthenticationVerificationResult selfResult =
        new AuthenticationVerifier()
            .verify(
                new AuthenticationVerificationRequest(
                    a.authenticatorData(),
                    a.clientDataJson(),
                    a.signature(),
                    a.challenge(),
                    List.of("https://example.com"),
                    "example.com",
                    a.storedCoseKeyBytes(),
                    false));

    // webauthn4j.
    WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();
    ObjectConverter objectConverter = new ObjectConverter();
    AttestedCredentialDataConverter conv = new AttestedCredentialDataConverter(objectConverter);
    var w4jData =
        manager.parse(
            new AuthenticationRequest(
                a.credentialId(),
                a.userHandle(),
                a.authenticatorData(),
                a.clientDataJson(),
                a.signature()));
    manager.verify(
        w4jData,
        new AuthenticationParameters(
            new ServerProperty(
                Set.of(new Origin("https://example.com")),
                "example.com",
                new DefaultChallenge(a.challenge())),
            new AuthenticatorImpl(
                conv.convert(a.storedCoseKeyBytes()), new NoneAttestationStatement(), 0),
            null,
            false,
            true));

    assertThat(selfResult.newSignCount())
        .isEqualTo(w4jData.getAuthenticatorData().getSignCount());
    assertThat(selfResult.userVerified())
        .isEqualTo(w4jData.getAuthenticatorData().isFlagUV());
  }
}
```

> **참고:** `Fido2Fixtures`는 `AuthenticationVerifierTest`의 `Fixture` 빌더를 `server/src/test/java/com/crosscert/passkey/unit/fido2/Fido2Fixtures.java`로 추출한 공유 헬퍼다. Task 6 Step 2의 `Fixture` 클래스를 별도 public 클래스로 옮기고, `Assertion` 레코드(`authenticatorData`, `clientDataJson`, `signature`, `challenge`, `storedCoseKeyBytes`, `credentialId`, `userHandle`)와 `validAssertion(origin, rpId)` 정적 메서드를 제공하도록 작성한다. `storedCoseKeyBytes`는 webauthn4j `AttestedCredentialDataConverter`가 읽을 수 있도록 `aaguid(16) + credIdLen(2) + credId + coseKey` 형식으로 만든다.

- [ ] **Step 6: 전체 검증**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.credential.service.AuthenticationServiceTest" --tests "com.crosscert.passkey.unit.fido2.*"`
Expected: PASS. 기존 `AuthenticationServiceTest`(fail-closed 분기)가 그대로 통과하고 차등 테스트도 통과.

- [ ] **Step 7: 슬라이스/통합 테스트 확인**

Run: `cd server && ./gradlew check`
Expected: PASS. 인증 슬라이스 테스트가 자체 코어로도 통과하는지 확인. 실패 시 fixture 형식 불일치를 추적해 수정.

- [ ] **Step 8: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/credential/service/AuthenticationService.java server/src/test/java/com/crosscert/passkey/unit/fido2/
git commit -m "feat(fido2): 인증 경로를 자체 FIDO2 코어로 교체 + 차등 테스트"
```

---

## Phase 2 — 등록(none / packed-self attestation) 경로 교체

attestation verifier(none, packed-self)와 `RegistrationVerifier`를 구현하고, `RegistrationService.finishRegistration()`를 자체 코어로 교체한 뒤 `webauthn4j-core` 의존성을 제거한다. packed-full / apple / TPM 등은 Milestone B 범위이므로 이 Phase에서는 미지원 포맷으로 명시 거부한다.

### Task 8: AttestationVerifier — none / packed-self

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationResult.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifier.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/NoneAttestationVerifier.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/PackedSelfAttestationVerifier.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/attestation/AttestationVerifiers.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/AttestationVerifierTest.java`

- [ ] **Step 1: `AttestationResult` + `AttestationVerifier` 인터페이스 작성**

`AttestationResult.java`:

```java
package com.crosscert.passkey.fido2.attestation;

/**
 * The outcome of attestation statement verification. {@code trustPathPresent} is {@code false} for
 * none and self attestation — Milestone A formats carry no certificate chain; Milestone B will set
 * it for full attestation backed by an MDS trust anchor.
 */
public record AttestationResult(String format, boolean trustPathPresent) {}
```

`AttestationVerifier.java`:

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.model.AttestationObject;

/**
 * Verifies one attestation statement format (WebAuthn L3 §8). Each implementation handles a single
 * {@code fmt} value. Milestone A ships {@code none} and {@code packed} (self attestation only);
 * Milestone B adds the certificate-chain formats. Sealed so the supported set is explicit.
 */
public sealed interface AttestationVerifier
    permits NoneAttestationVerifier, PackedSelfAttestationVerifier {

  /** The {@code fmt} string this verifier handles. */
  String format();

  /**
   * Verify the attestation statement of {@code attestationObject} against {@code clientDataHash}
   * (SHA-256 of clientDataJSON), or throw {@link Fido2VerificationException}.
   */
  AttestationResult verify(AttestationObject attestationObject, byte[] clientDataHash)
      throws Fido2VerificationException;
}
```

- [ ] **Step 2: `AttestationVerifierTest` 작성**

```java
package com.crosscert.passkey.unit.fido2.attestation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.AttestationVerifiers;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.unit.fido2.CborTestEncoder;
import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AttestationVerifierTest {

  @Test
  void verifies_none_attestation() throws Exception {
    AttestationObject obj = AttestationObject.parse(noneAttestationObject());
    AttestationResult result = AttestationVerifiers.forFormat("none").verify(obj, new byte[32]);
    assertThat(result.format()).isEqualTo("none");
    assertThat(result.trustPathPresent()).isFalse();
  }

  @Test
  void none_attestation_with_non_empty_statement_is_rejected() {
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    attStmt.put("x", 1L);
    AttestationObject obj = AttestationObject.parse(attestationObject("none", attStmt));
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("none").verify(obj, new byte[32]))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ATTESTATION_INVALID);
  }

  @Test
  void unsupported_format_is_rejected() {
    assertThatThrownBy(() -> AttestationVerifiers.forFormat("tpm"))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.UNSUPPORTED_ATTESTATION_FORMAT);
  }

  private static byte[] noneAttestationObject() {
    return attestationObject("none", new LinkedHashMap<>());
  }

  private static byte[] attestationObject(String fmt, Map<Object, Object> attStmt) {
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.writeBytes(new byte[32]);
    authData.write(0x41); // UP | AT
    authData.writeBytes(new byte[] {0, 0, 0, 0});
    authData.writeBytes(new byte[16]); // aaguid
    authData.writeBytes(new byte[] {0, 2}); // credIdLen
    authData.writeBytes(new byte[] {1, 2}); // credId
    authData.writeBytes(sampleCoseKey());

    Map<Object, Object> obj = new LinkedHashMap<>();
    obj.put("fmt", fmt);
    obj.put("attStmt", attStmt);
    obj.put("authData", authData.toByteArray());
    return CborTestEncoder.encodeMap(obj);
  }

  private static byte[] sampleCoseKey() {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L);
    m.put(3L, -7L);
    m.put(-1L, 1L);
    m.put(-2L, new byte[32]);
    m.put(-3L, new byte[32]);
    return CborTestEncoder.encodeMap(m);
  }
}
```

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AttestationVerifierTest"`
Expected: 컴파일 실패 — verifier 클래스 미존재.

- [ ] **Step 4: `NoneAttestationVerifier` 구현**

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.model.AttestationObject;

/**
 * The {@code none} attestation format (WebAuthn L3 §8.7): the authenticator provides no
 * attestation. The only check is that the attestation statement is empty — a non-empty statement
 * under {@code fmt=none} is malformed input and is rejected.
 */
public final class NoneAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "none";
  }

  @Override
  public AttestationResult verify(AttestationObject attestationObject, byte[] clientDataHash)
      throws Fido2VerificationException {
    if (!attestationObject.attestationStatement().isEmpty()) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "none attestation must have an empty statement");
    }
    return new AttestationResult("none", false);
  }
}
```

- [ ] **Step 5: `PackedSelfAttestationVerifier` 구현**

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * The {@code packed} attestation format (WebAuthn L3 §8.2), self-attestation variant only — the
 * statement carries {@code alg} and {@code sig} but no {@code x5c} certificate chain. The
 * signature is verified with the credential public key itself over {@code authData ||
 * clientDataHash}. The full (x5c) variant requires certificate-path validation and ships in
 * Milestone B; an {@code x5c} present here is rejected as an unsupported format.
 */
public final class PackedSelfAttestationVerifier implements AttestationVerifier {

  @Override
  public String format() {
    return "packed";
  }

  @Override
  public AttestationResult verify(AttestationObject attestationObject, byte[] clientDataHash)
      throws Fido2VerificationException {
    Map<?, ?> attStmt = attestationObject.attestationStatement();
    if (attStmt.containsKey("x5c")) {
      throw new Fido2VerificationException(
          FailureReason.UNSUPPORTED_ATTESTATION_FORMAT,
          "packed full attestation (x5c) is not supported in Milestone A");
    }
    Object sig = attStmt.get("sig");
    if (!(sig instanceof byte[] signature)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed attestation missing sig");
    }
    AttestedCredentialData acd = attestationObject.authenticatorData().attestedCredentialData();
    if (acd == null) {
      throw new Fido2VerificationException(
          FailureReason.NO_ATTESTED_CREDENTIAL, "attestation has no attested credential data");
    }
    CoseKey credentialKey = acd.coseKey();
    ByteArrayOutputStream signedData = new ByteArrayOutputStream();
    signedData.writeBytes(attestationObject.authenticatorData().rawBytes());
    signedData.writeBytes(clientDataHash);
    if (!CoseSignatureVerifier.verify(credentialKey, signedData.toByteArray(), signature)) {
      throw new Fido2VerificationException(
          FailureReason.ATTESTATION_INVALID, "packed self-attestation signature invalid");
    }
    return new AttestationResult("packed", false);
  }
}
```

- [ ] **Step 6: `AttestationVerifiers` 레지스트리 구현**

```java
package com.crosscert.passkey.fido2.attestation;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import java.util.Map;

/**
 * Dispatches an attestation {@code fmt} string to its {@link AttestationVerifier}. Milestone A
 * registers {@code none} and {@code packed}; any other format throws {@code
 * UNSUPPORTED_ATTESTATION_FORMAT} (fail-closed) until Milestone B adds it.
 */
public final class AttestationVerifiers {

  private static final Map<String, AttestationVerifier> REGISTRY =
      Map.of(
          "none", new NoneAttestationVerifier(),
          "packed", new PackedSelfAttestationVerifier());

  private AttestationVerifiers() {}

  /** Return the verifier for {@code fmt}, or throw if the format is not supported. */
  public static AttestationVerifier forFormat(String fmt) throws Fido2VerificationException {
    AttestationVerifier verifier = REGISTRY.get(fmt);
    if (verifier == null) {
      throw new Fido2VerificationException(
          FailureReason.UNSUPPORTED_ATTESTATION_FORMAT, "unsupported attestation format: " + fmt);
    }
    return verifier;
  }
}
```

- [ ] **Step 7: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.attestation.AttestationVerifierTest"`
Expected: PASS (3 tests).

- [ ] **Step 8: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/attestation/ server/src/test/java/com/crosscert/passkey/unit/fido2/attestation/
git commit -m "feat(fido2): none / packed-self AttestationVerifier 추가"
```

---

### Task 9: `RegistrationVerifier` 구현

**Files:**
- Create: `server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerificationRequest.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerificationResult.java`
- Create: `server/src/main/java/com/crosscert/passkey/fido2/RegistrationVerifier.java`
- Test: `server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationVerifierTest.java`

- [ ] **Step 1: 입력/출력 레코드 작성**

`RegistrationVerificationRequest.java`:

```java
package com.crosscert.passkey.fido2;

import java.util.List;

/**
 * Inputs for verifying a {@code navigator.credentials.create()} registration. {@code
 * attestationObject} and {@code clientDataJson} are the raw (base64url-decoded) ceremony outputs;
 * {@code expectedChallenge} is the raw challenge the server issued.
 */
public record RegistrationVerificationRequest(
    byte[] attestationObject,
    byte[] clientDataJson,
    byte[] expectedChallenge,
    List<String> expectedOrigins,
    String expectedRpId,
    boolean userVerificationRequired) {}
```

`RegistrationVerificationResult.java`:

```java
package com.crosscert.passkey.fido2;

/**
 * Verified facts extracted from a successful registration. The caller persists these and applies
 * tenant policy: {@code aaguid} feeds the AAGUID allow-list, {@code backupEligible} feeds the
 * syncable-credential policy. {@code attestedCredentialData} is the serialized {@code aaguid ||
 * credIdLen || credentialId || coseKey} blob — the exact form stored in {@code
 * credential.public_key_cose} and read back by {@code AuthenticationVerifier}.
 */
public record RegistrationVerificationResult(
    byte[] credentialId,
    byte[] attestedCredentialData,
    byte[] aaguid,
    long signCount,
    boolean userVerified,
    boolean backupEligible,
    boolean backupState,
    String attestationFormat) {}
```

- [ ] **Step 2: `RegistrationVerifierTest` 작성**

```java
package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
import java.util.List;
import org.junit.jupiter.api.Test;

class RegistrationVerifierTest {

  @Test
  void verifies_a_valid_none_attestation_registration() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    RegistrationVerificationResult result =
        new RegistrationVerifier()
            .verify(
                new RegistrationVerificationRequest(
                    r.attestationObject(),
                    r.clientDataJson(),
                    r.challenge(),
                    List.of("https://example.com"),
                    "example.com",
                    false));
    assertThat(result.attestationFormat()).isEqualTo("none");
    assertThat(result.credentialId()).isEqualTo(r.credentialId());
    assertThat(result.signCount()).isEqualTo(r.signCount());
  }

  @Test
  void rejects_wrong_ceremony_type() throws Exception {
    // clientData.type == webauthn.get on a registration → WRONG_CEREMONY_TYPE
    Fido2Fixtures.Registration r =
        Fido2Fixtures.registrationWithClientType("webauthn.get", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            r.challenge(),
                            List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.WRONG_CEREMONY_TYPE);
  }

  @Test
  void rejects_challenge_mismatch() throws Exception {
    Fido2Fixtures.Registration r =
        Fido2Fixtures.validRegistration("none", "https://example.com", "example.com");
    assertThatThrownBy(
            () ->
                new RegistrationVerifier()
                    .verify(
                        new RegistrationVerificationRequest(
                            r.attestationObject(),
                            r.clientDataJson(),
                            "d3Jvbmc".getBytes(),
                            List.of("https://example.com"),
                            "example.com",
                            false)))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.CHALLENGE_MISMATCH);
  }
}
```

> **참고:** `Fido2Fixtures`에 `Registration` 레코드(`attestationObject`, `clientDataJson`, `challenge`, `credentialId`, `signCount`)와 `validRegistration(fmt, origin, rpId)` / `registrationWithClientType(type, origin, rpId)` 정적 메서드를 추가한다. `validRegistration("none", ...)`는 빈 attStmt + AT 플래그가 선 authData를 가진 attestationObject를 `CborTestEncoder`로 만든다. `validRegistration("packed", ...)`는 credential 키로 `authData||clientHash`를 서명한 `sig`를 attStmt에 넣는다.

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.RegistrationVerifierTest"`
Expected: 컴파일 실패 — `RegistrationVerifier` 미존재.

- [ ] **Step 4: `RegistrationVerifier` 구현**

```java
package com.crosscert.passkey.fido2;

import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.AttestationVerifiers;
import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.model.AuthenticatorData;
import com.crosscert.passkey.fido2.model.CollectedClientData;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Verifies a {@code navigator.credentials.create()} registration against the WebAuthn L3 §7.1
 * algorithm: client data type / challenge / origin, the RP id hash, the user-presence and
 * user-verification flags, the presence of attested credential data, and the attestation
 * statement. It returns the verified facts; tenant policy (AAGUID allow-list, syncable policy,
 * MDS) stays with the caller.
 */
public final class RegistrationVerifier {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

  /** Verify the registration described by {@code req}, or throw {@link Fido2VerificationException}. */
  public RegistrationVerificationResult verify(RegistrationVerificationRequest req)
      throws Fido2VerificationException {
    CollectedClientData clientData = parseClientData(req.clientDataJson());
    if (!"webauthn.create".equals(clientData.type())) {
      throw new Fido2VerificationException(
          FailureReason.WRONG_CEREMONY_TYPE, "clientData.type is not webauthn.create");
    }
    if (!constantTimeEquals(decodeB64Url(clientData.challenge()), req.expectedChallenge())) {
      throw new Fido2VerificationException(
          FailureReason.CHALLENGE_MISMATCH, "registration challenge does not match");
    }
    if (!req.expectedOrigins().contains(clientData.origin())) {
      throw new Fido2VerificationException(
          FailureReason.ORIGIN_MISMATCH, "origin not allow-listed: " + clientData.origin());
    }

    AttestationObject attestationObject = parseAttestationObject(req.attestationObject());
    AuthenticatorData authData = attestationObject.authenticatorData();
    verifyRpIdHash(authData, req.expectedRpId());
    if (!authData.flags().userPresent()) {
      throw new Fido2VerificationException(
          FailureReason.UP_FLAG_MISSING, "user-presence flag not set");
    }
    if (req.userVerificationRequired() && !authData.flags().userVerified()) {
      throw new Fido2VerificationException(
          FailureReason.UV_FLAG_REQUIRED, "user-verification required but flag not set");
    }
    AttestedCredentialData acd = authData.attestedCredentialData();
    if (acd == null) {
      throw new Fido2VerificationException(
          FailureReason.NO_ATTESTED_CREDENTIAL, "registration has no attested credential data");
    }

    byte[] clientDataHash = sha256(req.clientDataJson());
    AttestationResult attestation =
        AttestationVerifiers.forFormat(attestationObject.format())
            .verify(attestationObject, clientDataHash);

    return new RegistrationVerificationResult(
        acd.credentialId(),
        serializeAttestedCredentialData(acd),
        acd.aaguid(),
        authData.signCount(),
        authData.flags().userVerified(),
        authData.flags().backupEligible(),
        authData.flags().backupState(),
        attestation.format());
  }

  /**
   * Serialize attested credential data into the {@code aaguid(16) || credIdLen(2) || credentialId
   * || coseKey} layout that {@code credential.public_key_cose} stores — identical to the form
   * webauthn4j's {@code AttestedCredentialDataConverter} produced, so existing rows stay readable.
   */
  private static byte[] serializeAttestedCredentialData(AttestedCredentialData acd) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(acd.aaguid());
    int len = acd.credentialId().length;
    out.write((len >> 8) & 0xff);
    out.write(len & 0xff);
    out.writeBytes(acd.credentialId());
    out.writeBytes(acd.coseKeyBytes());
    return out.toByteArray();
  }

  private void verifyRpIdHash(AuthenticatorData authData, String rpId)
      throws Fido2VerificationException {
    byte[] expected = sha256(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    if (!constantTimeEquals(expected, authData.rpIdHash())) {
      throw new Fido2VerificationException(
          FailureReason.RPID_HASH_MISMATCH, "authenticator rpIdHash does not match RP id");
    }
  }

  private static CollectedClientData parseClientData(byte[] json)
      throws Fido2VerificationException {
    try {
      return CollectedClientData.parse(json);
    } catch (CborDecodeException e) {
      throw new Fido2VerificationException(FailureReason.MALFORMED_CLIENT_DATA, e.getMessage());
    }
  }

  private static AttestationObject parseAttestationObject(byte[] raw)
      throws Fido2VerificationException {
    try {
      return AttestationObject.parse(raw);
    } catch (CborDecodeException e) {
      throw new Fido2VerificationException(FailureReason.MALFORMED_CBOR, e.getMessage());
    }
  }

  private static byte[] decodeB64Url(String s) throws Fido2VerificationException {
    try {
      return B64URL.decode(s);
    } catch (IllegalArgumentException e) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CLIENT_DATA, "challenge is not valid base64url");
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static boolean constantTimeEquals(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }
}
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `cd server && ./gradlew test --tests "com.crosscert.passkey.unit.fido2.RegistrationVerifierTest"`
Expected: PASS (3 tests).

- [ ] **Step 6: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/fido2/Registration*.java server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationVerifierTest.java server/src/test/java/com/crosscert/passkey/unit/fido2/Fido2Fixtures.java
git commit -m "feat(fido2): RegistrationVerifier — attestation 검증 구현"
```

---

### Task 10: `RegistrationService.finishRegistration()` 교체

**Files:**
- Modify: `server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java`

`finishRegistration()`의 parse/verify 블록만 자체 코어로 교체한다. `beginRegistration`, `buildExtensions`, AAGUID/syncable 정책 판단, audit, `Credential.create` 호출은 결과 레코드 필드명만 맞춰 유지한다.

> **Milestone A 제약:** `RegistrationService`는 `mdsStrict` 정책일 때 `strictWebAuthnManager`(webauthn4j-metadata)를 쓴다. MDS는 Milestone B 범위이므로, **Phase 2에서는 `nonStrictManager` 경로만 자체 코어로 교체하고 strict 경로는 webauthn4j를 유지**한다. 즉 `strictManagerProvider`·`policy.isMdsStrict()` 분기와 그 안의 webauthn4j 호출은 그대로 둔다. `webauthn4j-core`는 strict 매니저(`WebAuthnConfig.strictWebAuthnManager`)가 의존하므로 **Phase 2 종료 시점에는 제거하지 않는다** — 제거는 Milestone B Phase 4에서 수행한다.

- [ ] **Step 1: import 추가**

`RegistrationService.java`에 추가:

```java
import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.RegistrationVerificationRequest;
import com.crosscert.passkey.fido2.RegistrationVerificationResult;
import com.crosscert.passkey.fido2.RegistrationVerifier;
```

- [ ] **Step 2: non-strict parse/verify 블록을 자체 코어로 교체**

`finishRegistration()`에서 `WebAuthnManager manager = nonStrictManager;`로 시작하는 블록부터 `regData = manager.parse(...)` / `manager.verify(...)` try-catch 블록까지를 검토한다. **strict 분기는 그대로 두고**, non-strict 검증을 자체 코어로 분리한다. 기존:

```java
    RegistrationData regData;
    try {
      regData = manager.parse(registrationRequest);
      manager.verify(regData, params);
    } catch (BadStatusException e) {
      ...
    }
```

이 try-catch에서 `manager`가 `nonStrictManager`인 경우(= `!policy.isMdsStrict()`)를 자체 코어로 분기한다. `policy.isMdsStrict()` 분기 직후 다음 구조로 재작성:

```java
    AttestationFacts facts;
    if (policy.isMdsStrict()) {
      // MDS strict path stays on webauthn4j until Milestone B.
      WebAuthnManager manager = strictManagerProvider.getIfAvailable();
      if (manager == null) {
        log.error(
            "register.mds.unavailable tenantId={} tenantUserId={} — "
                + "tenant requires mdsStrict but server has passkey.mds.enabled=false",
            cfg.getTenantId(),
            stored.tenantUserId());
        metrics.getRegistrationFailure().increment();
        throw new BusinessException(ErrorCode.MDS_UNAVAILABLE);
      }
      log.info(
          "register.mds.strict.engaged tenantId={} tenantUserId={}",
          cfg.getTenantId(),
          stored.tenantUserId());
      facts = verifyWithWebauthn4j(manager, registrationRequest, params, cfg, stored);
    } else {
      facts = verifyWithCore(cfg, stored, req);
    }
```

`AttestationFacts`는 두 경로의 결과를 통일하는 `RegistrationService` 내부 private record로 추가:

```java
  /** Verified attestation facts, normalized across the self-core and webauthn4j strict paths. */
  private record AttestationFacts(
      String credentialIdB64u,
      byte[] attestedCredentialData,
      UUID aaguid,
      long signatureCounter,
      boolean backupEligible,
      boolean backupState) {}
```

- [ ] **Step 3: `verifyWithCore` private 메서드 추가**

`RegistrationService`에 추가. `serverProperty`/`params`/`RegistrationRequest` 등 webauthn4j 객체 조립 코드는 non-strict 경로에서는 더 이상 필요 없다 — `verifyWithCore`가 자체 입력 레코드를 직접 만든다:

```java
  private AttestationFacts verifyWithCore(
      TenantWebauthnConfig cfg, ChallengeRecord stored, RegistrationVerifyRequest req) {
    RegistrationVerificationRequest verifyReq =
        new RegistrationVerificationRequest(
            Base64UrlCodec.decode(req.attestationObjectB64u()),
            Base64UrlCodec.decode(req.clientDataJsonB64u()),
            Base64UrlCodec.decode(stored.challengeB64u()),
            cfg.originList(),
            cfg.getRpId(),
            cfg.getUserVerification().isStrictRequired());
    RegistrationVerificationResult result;
    try {
      result = new RegistrationVerifier().verify(verifyReq);
    } catch (Fido2VerificationException e) {
      log.warn(
          "register.attestation.invalid tenantId={} tenantUserId={} reason={} detail={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.reason(),
          e.getMessage());
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.ATTESTATION_INVALID, e.getMessage());
    }
    UUID aaguid = bytesToUuid(result.aaguid());
    return new AttestationFacts(
        Base64UrlCodec.encode(result.credentialId()),
        result.attestedCredentialData(),
        aaguid,
        result.signCount(),
        result.backupEligible(),
        result.backupState());
  }

  /** Decode a 16-byte AAGUID into a {@link UUID}; an all-zero AAGUID maps to {@code null}. */
  private static UUID bytesToUuid(byte[] aaguid) {
    if (aaguid == null || aaguid.length != 16) {
      return null;
    }
    boolean allZero = true;
    for (byte b : aaguid) {
      if (b != 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      return null;
    }
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(aaguid);
    return new UUID(buf.getLong(), buf.getLong());
  }
```

- [ ] **Step 4: `verifyWithWebauthn4j` private 메서드로 strict 경로 추출**

기존 webauthn4j parse/verify try-catch 블록과 그 뒤의 `AttestedCredentialData acd = ...` 추출 코드를 `verifyWithWebauthn4j`로 그대로 옮긴다. 결과를 `AttestationFacts`로 반환:

```java
  private AttestationFacts verifyWithWebauthn4j(
      WebAuthnManager manager,
      RegistrationRequest registrationRequest,
      RegistrationParameters params,
      TenantWebauthnConfig cfg,
      ChallengeRecord stored) {
    RegistrationData regData;
    try {
      regData = manager.parse(registrationRequest);
      manager.verify(regData, params);
    } catch (BadStatusException e) {
      log.error(
          "register.authenticator.revoked tenantId={} tenantUserId={} reason={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.getMessage());
      auditService.append(
          com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          stored.tenantUserId().toString(),
          "AUTHENTICATOR",
          "revoked",
          java.util.Map.of("reason", String.valueOf(e.getMessage())));
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.AUTHENTICATOR_REVOKED, e.getMessage());
    } catch (TrustAnchorNotFoundException e) {
      log.warn(
          "register.mds.trust_failed tenantId={} tenantUserId={} reason={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.getMessage());
      auditService.append(
          com.crosscert.passkey.audit.domain.AuditEventType.ATTESTATION_TRUST_FAILED,
          com.crosscert.passkey.audit.domain.ActorType.END_USER,
          stored.tenantUserId().toString(),
          "AUTHENTICATOR",
          "trust_anchor_missing",
          java.util.Map.of("reason", String.valueOf(e.getMessage())));
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.MDS_TRUST_FAILED, e.getMessage());
    } catch (DataConversionException | VerificationException e) {
      log.warn(
          "register.attestation.invalid tenantId={} tenantUserId={} reason={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          e.getMessage());
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.ATTESTATION_INVALID, e.getMessage());
    }
    AttestedCredentialData acd =
        regData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
    AAGUID aaguidObj = acd.getAaguid();
    UUID aaguid = aaguidObj == null ? null : aaguidObj.getValue();
    return new AttestationFacts(
        Base64UrlCodec.encode(acd.getCredentialId()),
        attestedConverter.convert(acd),
        aaguid,
        regData.getAttestationObject().getAuthenticatorData().getSignCount(),
        regData.getAttestationObject().getAuthenticatorData().isFlagBE(),
        regData.getAttestationObject().getAuthenticatorData().isFlagBS());
  }
```

- [ ] **Step 5: `finishRegistration()` 후반부를 `AttestationFacts` 기준으로 조정**

기존 `AttestedCredentialData acd = ...` ~ `Credential.create(...)` 사이 코드를 `facts` 필드 참조로 교체:

```java
    UUID aaguid = facts.aaguid();
    if (!policy.accepts(aaguid)) {
      log.warn(
          "register.aaguid.rejected tenantId={} tenantUserId={} aaguid={} policyMode={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          aaguid,
          policy.getMode());
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.AAGUID_NOT_ALLOWED);
    }

    long signatureCounter = facts.signatureCounter();
    boolean backupEligible = facts.backupEligible();
    boolean backupState = facts.backupState();

    if (!policy.acceptsSyncable(backupEligible)) {
      log.warn(
          "register.syncable.rejected tenantId={} tenantUserId={} aaguid={} backupEligible={}",
          cfg.getTenantId(),
          stored.tenantUserId(),
          aaguid,
          backupEligible);
      metrics.getRegistrationFailure().increment();
      throw new BusinessException(ErrorCode.SYNCABLE_NOT_ALLOWED);
    }

    Credential credential =
        Credential.create(
            cfg.getTenantId(),
            stored.tenantUserId(),
            facts.credentialIdB64u(),
            facts.attestedCredentialData(),
            aaguid,
            req.transports(),
            stored.userHandleB64u(),
            signatureCounter,
            backupEligible,
            backupState);
```

- [ ] **Step 6: 차등 테스트 추가**

`server/src/test/java/com/crosscert/passkey/unit/fido2/RegistrationDifferentialTest.java` 생성. `Fido2Fixtures.validRegistration("none", ...)`와 `("packed", ...)` 출력을 webauthn4j `WebAuthnManager.createNonStrictWebAuthnManager()`와 자체 `RegistrationVerifier` 양쪽에 넣어 `credentialId`·`aaguid`·`signCount`·BE/BS 일치를 확인한다 (Task 7 Step 5 차등 테스트와 동일 구조, 등록 버전).

- [ ] **Step 7: 전체 검증**

Run: `cd server && ./gradlew check`
Expected: PASS. 기존 `RegistrationServiceTest` + 등록 슬라이스 테스트 + 차등 테스트 모두 통과. 실패 시 `attestedCredentialData` 직렬화 형식이 webauthn4j와 바이트 단위로 일치하는지 차등 테스트로 추적.

- [ ] **Step 8: 포맷 + 커밋**

```bash
cd server && ./gradlew spotlessApply
git add server/src/main/java/com/crosscert/passkey/credential/service/RegistrationService.java server/src/test/java/com/crosscert/passkey/unit/fido2/
git commit -m "feat(fido2): 등록 non-strict 경로를 자체 FIDO2 코어로 교체 + 차등 테스트"
```

---

### Task 11: Milestone A 마무리 — 문서 갱신

**Files:**
- Modify: `docs/architecture.md`
- Modify: `server/src/main/java/com/crosscert/passkey/credential/package-info.java`

`webauthn4j-core`/`webauthn4j-metadata` 의존성은 strict(MDS) 경로가 여전히 사용하므로 **Milestone A에서는 제거하지 않는다**. 제거는 Milestone B Phase 4의 완료 기준이다.

- [ ] **Step 1: `architecture.md` 갱신**

`docs/architecture.md`의 WebAuthn 검증 관련 섹션에 `com.crosscert.passkey.fido2` 자체 코어를 추가 기술하고, "non-strict(기본) 경로 = 자체 FIDO2 코어, strict(mdsStrict) 경로 = webauthn4j (Milestone B에서 교체 예정)"을 명시한다. §10 변경 이력에 항목을 추가한다.

- [ ] **Step 2: `credential/package-info.java`의 webauthn4j 언급 갱신**

`package-info.java`에서 webauthn4j를 단독 검증 엔진으로 서술한 부분을, non-strict는 자체 `fido2` 코어가 담당하도록 갱신한다.

- [ ] **Step 3: 전체 검증 + 커밋**

```bash
cd server && ./gradlew check
git add docs/architecture.md server/src/main/java/com/crosscert/passkey/credential/package-info.java
git commit -m "docs: FIDO2 코어 자체 구현(Milestone A) 반영 — architecture.md 갱신"
```

---

## Milestone A 완료 기준

- [ ] `com.crosscert.passkey.fido2` 패키지 신설 — CBOR/COSE/model/attestation + Registration·AuthenticationVerifier
- [ ] 인증(assertion) 경로가 자체 코어로 동작 (Phase 1)
- [ ] 등록 non-strict(none/packed-self) 경로가 자체 코어로 동작 (Phase 2)
- [ ] 등록 strict(mdsStrict) 경로는 webauthn4j 유지 — Milestone B 대상
- [ ] `webauthn4j-core` / `webauthn4j-metadata` 의존성 잔존 (strict 경로가 사용) — 제거는 Milestone B
- [ ] ArchUnit Rule 7(`fido2` 순수성) 통과
- [ ] 인증·등록 차등 테스트(webauthn4j vs 자체 코어) 통과
- [ ] `./gradlew check` 통과

## Milestone B 예고 (별도 계획)

- Phase 3: packed-full / apple-anonymous / android-key attestation + X.509 cert path 검증
- Phase 4: TPM / android-safetynet / U2F attestation + FIDO MDS3 BLOB 파싱·trust anchor → strict 경로 자체 코어 교체 → `webauthn4j-core`·`webauthn4j-metadata` 완전 제거 → `WebAuthnConfig`·`credential/metadata/*` 정리
