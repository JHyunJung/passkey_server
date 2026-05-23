package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
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

/**
 * Golden-vector tests for {@link AuthenticationVerifier}. Replaces the webauthn4j-based assertion
 * differential test with self-built deterministic vectors. Each test asserts the verifier produces
 * the expected facts without relying on any external library comparison.
 *
 * <p>Future: extend with W3C L3 spec examples and FIDO conformance vectors (Phase 5 backlog, see
 * docs/superpowers/specs §11.3).
 */
class AssertionGoldenVectorTest {

  // ── Positive cases ─────────────────────────────────────────────────────────

  @Test
  void valid_assertion_with_up_and_uv_flags() throws Exception {
    // UP(0x01) | UV(0x04) — standard user-present + user-verified assertion, signCount=42.
    AssertionFixture f = new AssertionFixture(0x01 | 0x04, 42, "https://example.com");

    AuthenticationVerificationResult result = new AuthenticationVerifier().verify(f.request());

    assertThat(result.newSignCount()).isEqualTo(42L);
    assertThat(result.userVerified()).isTrue();
    assertThat(result.backupEligible()).isFalse();
    assertThat(result.backupState()).isFalse();
    assertThat(result.crossOrigin()).isFalse();
  }

  @Test
  void valid_assertion_with_backup_flags() throws Exception {
    // UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) — backup-eligible and backed-up credential.
    AssertionFixture f = new AssertionFixture(0x01 | 0x04 | 0x08 | 0x10, 99, "https://example.com");

    AuthenticationVerificationResult result = new AuthenticationVerifier().verify(f.request());

    assertThat(result.newSignCount()).isEqualTo(99L);
    assertThat(result.userVerified()).isTrue();
    assertThat(result.backupEligible()).isTrue();
    assertThat(result.backupState()).isTrue();
  }

  @Test
  void assertion_sign_count_zero_is_valid() throws Exception {
    // signCount=0 is a valid passkey value (platform authenticators may always use 0).
    AssertionFixture f = new AssertionFixture(0x01 | 0x04, 0, "https://example.com");

    AuthenticationVerificationResult result = new AuthenticationVerifier().verify(f.request());

    assertThat(result.newSignCount()).isEqualTo(0L);
  }

  // ── Negative cases — golden rejection vectors ──────────────────────────────

  @Test
  void golden_vector_rejects_tampered_signature() throws Exception {
    AssertionFixture f = new AssertionFixture(0x01 | 0x04, 42, "https://example.com");
    byte[] tamperedSig = f.signature.clone();
    tamperedSig[tamperedSig.length - 1] ^= 0xFF; // flip last byte

    AuthenticationVerificationRequest req =
        new AuthenticationVerificationRequest(
            f.authenticatorData,
            f.clientDataJsonBytes,
            tamperedSig,
            f.challengeBytes,
            List.of(f.origin),
            f.rpId,
            f.storedCoseKeyBytes,
            false);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.SIGNATURE_INVALID);
  }

  @Test
  void golden_vector_rejects_challenge_mismatch() throws Exception {
    AssertionFixture f = new AssertionFixture(0x01 | 0x04, 42, "https://example.com");
    byte[] wrongChallenge = "a-different-challenge".getBytes(StandardCharsets.UTF_8);

    AuthenticationVerificationRequest req =
        new AuthenticationVerificationRequest(
            f.authenticatorData,
            f.clientDataJsonBytes,
            f.signature,
            wrongChallenge,
            List.of(f.origin),
            f.rpId,
            f.storedCoseKeyBytes,
            false);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.CHALLENGE_MISMATCH);
  }

  @Test
  void golden_vector_rejects_origin_mismatch() throws Exception {
    // clientDataJSON carries an origin outside the allow-list.
    AssertionFixture f = new AssertionFixture(0x01 | 0x04, 42, "https://evil.example.com");

    AuthenticationVerificationRequest req =
        new AuthenticationVerificationRequest(
            f.authenticatorData,
            f.clientDataJsonBytes,
            f.signature,
            f.challengeBytes,
            List.of("https://example.com"), // allow-list excludes the evil origin
            f.rpId,
            f.storedCoseKeyBytes,
            false);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(req))
        .isInstanceOf(Fido2VerificationException.class)
        .extracting(e -> ((Fido2VerificationException) e).reason())
        .isEqualTo(FailureReason.ORIGIN_MISMATCH);
  }

  // ── Fixture ───────────────────────────────────────────────────────────────

  /**
   * Builds a self-consistent assertion: a real EC P-256 key, a real ECDSA signature over {@code
   * authData || SHA-256(clientDataJSON)}, no external library dependency.
   */
  private static final class AssertionFixture {
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    final String rpId = "example.com";
    final String origin;
    final KeyPair keyPair;
    final byte[] storedCoseKeyBytes;
    final byte[] authenticatorData;
    final byte[] clientDataJsonBytes;
    final byte[] challengeBytes = "test-challenge-bytes".getBytes(StandardCharsets.UTF_8);
    final byte[] signature;

    AssertionFixture(int flags, int signCount, String origin) throws Exception {
      this.origin = origin;

      // Real EC P-256 key pair.
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec("secp256r1"));
      this.keyPair = gen.generateKeyPair();

      // storedCoseKeyBytes — AttestedCredentialData serialized form:
      // aaguid(16) + credIdLen(2) + credId + COSE key map.
      byte[] coseKeyMap = buildEs256CoseKey((ECPublicKey) keyPair.getPublic());
      byte[] credId = new byte[] {0x01, 0x02, 0x03, 0x04};
      ByteArrayOutputStream acdOut = new ByteArrayOutputStream();
      acdOut.writeBytes(new byte[16]); // aaguid (zeros)
      acdOut.write((credId.length >> 8) & 0xff);
      acdOut.write(credId.length & 0xff);
      acdOut.writeBytes(credId);
      acdOut.writeBytes(coseKeyMap);
      this.storedCoseKeyBytes = acdOut.toByteArray();

      // authenticatorData — rpIdHash(32) + flags(1) + signCount(4).
      byte[] rpIdHash =
          MessageDigest.getInstance("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
      ByteArrayOutputStream adOut = new ByteArrayOutputStream();
      adOut.writeBytes(rpIdHash);
      adOut.write(flags & 0xff);
      adOut.writeBytes(
          new byte[] {
            (byte) (signCount >> 24),
            (byte) (signCount >> 16),
            (byte) (signCount >> 8),
            (byte) signCount
          });
      this.authenticatorData = adOut.toByteArray();

      // clientDataJSON.
      String clientDataJson =
          "{\"type\":\"webauthn.get\",\"challenge\":\""
              + B64URL.encodeToString(challengeBytes)
              + "\",\"origin\":\""
              + origin
              + "\"}";
      this.clientDataJsonBytes = clientDataJson.getBytes(StandardCharsets.UTF_8);

      // Real signature over authData || SHA-256(clientDataJSON).
      byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJsonBytes);
      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.writeBytes(authenticatorData);
      signedData.writeBytes(clientDataHash);
      Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(keyPair.getPrivate());
      signer.update(signedData.toByteArray());
      this.signature = signer.sign();
    }

    AuthenticationVerificationRequest request() {
      return new AuthenticationVerificationRequest(
          authenticatorData,
          clientDataJsonBytes,
          signature,
          challengeBytes,
          List.of(origin),
          rpId,
          storedCoseKeyBytes,
          false);
    }

    private static byte[] buildEs256CoseKey(ECPublicKey pub) {
      Map<Object, Object> m = new LinkedHashMap<>();
      m.put(1L, 2L); // kty = EC2
      m.put(3L, -7L); // alg = ES256
      m.put(-1L, 1L); // crv = P-256
      m.put(-2L, fixedCoordinate(pub.getW().getAffineX())); // x
      m.put(-3L, fixedCoordinate(pub.getW().getAffineY())); // y
      return CborTestEncoder.encodeMap(m);
    }

    private static byte[] fixedCoordinate(BigInteger v) {
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
