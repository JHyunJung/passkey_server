package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
import com.crosscert.passkey.fido2.Fido2VerificationException;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
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
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Differential test: verifies that the self-core {@link AuthenticationVerifier} and webauthn4j
 * {@link WebAuthnManager} produce identical results for the same assertion input — both for the
 * happy path (signCount / UV / BE / BS agreement) and for rejection paths (tampered signature,
 * challenge mismatch, origin mismatch). This is the safety net guarding the migration until
 * webauthn4j is dropped entirely.
 */
class AssertionDifferentialTest {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  // ── Positive cases ─────────────────────────────────────────────────────────

  @Test
  void self_core_and_webauthn4j_agree_on_valid_assertion() throws Exception {
    Fixture f = new Fixture(0x01 | 0x04, 42); // UP + UV

    AuthenticationVerificationResult selfResult =
        new AuthenticationVerifier().verify(f.selfRequest());
    AuthenticationData w4jData = f.webauthn4jVerify();

    assertThat(selfResult.newSignCount())
        .as("signCount: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().getSignCount());
    assertThat(selfResult.userVerified())
        .as("userVerified: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().isFlagUV());
    assertThat(selfResult.backupEligible())
        .as("backupEligible: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().isFlagBE());
    assertThat(selfResult.backupState())
        .as("backupState: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().isFlagBS());

    // Sanity-check expected values
    assertThat(selfResult.newSignCount()).isEqualTo(42L);
    assertThat(selfResult.userVerified()).isTrue();
    assertThat(selfResult.backupEligible()).isFalse();
    assertThat(selfResult.backupState()).isFalse();
  }

  @Test
  void self_core_and_webauthn4j_agree_on_backup_flags() throws Exception {
    // flags = UP | UV | BE | BS = 0x1D — backup-eligible, backed-up credential.
    Fixture f = new Fixture(0x01 | 0x04 | 0x08 | 0x10, 99);

    AuthenticationVerificationResult selfResult =
        new AuthenticationVerifier().verify(f.selfRequest());
    AuthenticationData w4jData = f.webauthn4jVerify();

    assertThat(selfResult.backupEligible())
        .as("backupEligible: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().isFlagBE());
    assertThat(selfResult.backupState())
        .as("backupState: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().isFlagBS());
    assertThat(selfResult.newSignCount())
        .as("signCount: self-core vs webauthn4j")
        .isEqualTo(w4jData.getAuthenticatorData().getSignCount());

    // Sanity-check: both BE and BS bits surface as true.
    assertThat(selfResult.backupEligible()).isTrue();
    assertThat(selfResult.backupState()).isTrue();
  }

  // ── Negative cases — both implementations must reject the same bad input ───

  @Test
  void self_core_and_webauthn4j_both_reject_tampered_signature() throws Exception {
    Fixture f = new Fixture(0x01 | 0x04, 42);
    byte[] tamperedSig = f.signature.clone();
    tamperedSig[tamperedSig.length - 1] ^= 0xFF; // flip last byte

    AuthenticationVerificationRequest selfReq =
        new AuthenticationVerificationRequest(
            f.authenticatorData,
            f.clientDataJsonBytes,
            tamperedSig,
            f.challengeBytes,
            List.of(f.origin),
            f.rpId,
            f.storedCoseKeyBytes,
            false);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(selfReq))
        .isInstanceOf(Fido2VerificationException.class);

    assertThatThrownBy(
            () -> {
              WebAuthnManager m = WebAuthnManager.createNonStrictWebAuthnManager();
              AuthenticationData data =
                  m.parse(
                      new AuthenticationRequest(
                          f.credId, null, f.authenticatorData, f.clientDataJsonBytes, tamperedSig));
              m.verify(data, f.webauthn4jParams());
            })
        .isInstanceOf(Exception.class);
  }

  @Test
  void self_core_and_webauthn4j_both_reject_challenge_mismatch() throws Exception {
    Fixture f = new Fixture(0x01 | 0x04, 42);
    byte[] wrongChallenge = "a-different-challenge".getBytes(StandardCharsets.UTF_8);

    AuthenticationVerificationRequest selfReq =
        new AuthenticationVerificationRequest(
            f.authenticatorData,
            f.clientDataJsonBytes,
            f.signature,
            wrongChallenge,
            List.of(f.origin),
            f.rpId,
            f.storedCoseKeyBytes,
            false);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(selfReq))
        .isInstanceOf(Fido2VerificationException.class);

    assertThatThrownBy(
            () -> {
              WebAuthnManager m = WebAuthnManager.createNonStrictWebAuthnManager();
              ServerProperty wrongChallengeProp =
                  new ServerProperty(
                      Set.of(new Origin(f.origin)), f.rpId, new DefaultChallenge(wrongChallenge));
              AuthenticationParameters params =
                  new AuthenticationParameters(
                      wrongChallengeProp,
                      new AuthenticatorImpl(
                          f.attestedCredentialData(), new NoneAttestationStatement(), 0L),
                      null,
                      false,
                      true);
              AuthenticationData data =
                  m.parse(
                      new AuthenticationRequest(
                          f.credId, null, f.authenticatorData, f.clientDataJsonBytes, f.signature));
              m.verify(data, params);
            })
        .isInstanceOf(Exception.class);
  }

  @Test
  void self_core_and_webauthn4j_both_reject_origin_mismatch() throws Exception {
    // clientDataJSON carries an origin outside the allow-list.
    Fixture f = new Fixture(0x01 | 0x04, 42, "https://evil.example.com");

    AuthenticationVerificationRequest selfReq =
        new AuthenticationVerificationRequest(
            f.authenticatorData,
            f.clientDataJsonBytes,
            f.signature,
            f.challengeBytes,
            List.of("https://example.com"), // allow-list excludes the evil origin
            f.rpId,
            f.storedCoseKeyBytes,
            false);
    assertThatThrownBy(() -> new AuthenticationVerifier().verify(selfReq))
        .isInstanceOf(Fido2VerificationException.class);

    assertThatThrownBy(
            () -> {
              WebAuthnManager m = WebAuthnManager.createNonStrictWebAuthnManager();
              ServerProperty allowListProp =
                  new ServerProperty(
                      Set.of(new Origin("https://example.com")),
                      f.rpId,
                      new DefaultChallenge(f.challengeBytes));
              AuthenticationParameters params =
                  new AuthenticationParameters(
                      allowListProp,
                      new AuthenticatorImpl(
                          f.attestedCredentialData(), new NoneAttestationStatement(), 0L),
                      null,
                      false,
                      true);
              AuthenticationData data =
                  m.parse(
                      new AuthenticationRequest(
                          f.credId, null, f.authenticatorData, f.clientDataJsonBytes, f.signature));
              m.verify(data, params);
            })
        .isInstanceOf(Exception.class);
  }

  /**
   * Builds a self-consistent assertion: a real EC P-256 key, a real ECDSA signature over {@code
   * authData || SHA-256(clientDataJSON)}, and the matching webauthn4j wiring.
   */
  private static final class Fixture {
    final String rpId = "example.com";
    final String origin;
    final KeyPair keyPair;
    final byte[] storedCoseKeyBytes;
    final byte[] credId = {0x01, 0x02, 0x03, 0x04};
    final byte[] authenticatorData;
    final byte[] clientDataJsonBytes;
    final byte[] challengeBytes = "test-challenge-bytes".getBytes(StandardCharsets.UTF_8);
    final byte[] signature;

    Fixture(int flags, int signCount) throws Exception {
      this(flags, signCount, "https://example.com");
    }

    Fixture(int flags, int signCount, String origin) throws Exception {
      this.origin = origin;

      // Real EC P-256 key pair.
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec("secp256r1"));
      this.keyPair = gen.generateKeyPair();

      // storedCoseKeyBytes — AttestedCredentialData serialized form:
      // aaguid(16) + credIdLen(2) + credId + COSE key map.
      byte[] coseKeyMap = buildEs256CoseKey((ECPublicKey) keyPair.getPublic());
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
      adOut.write(flags);
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

    AuthenticationVerificationRequest selfRequest() {
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

    com.webauthn4j.data.attestation.authenticator.AttestedCredentialData attestedCredentialData() {
      return new AttestedCredentialDataConverter(new ObjectConverter()).convert(storedCoseKeyBytes);
    }

    AuthenticationParameters webauthn4jParams() {
      ServerProperty serverProperty =
          new ServerProperty(
              Set.of(new Origin(origin)), rpId, new DefaultChallenge(challengeBytes));
      return new AuthenticationParameters(
          serverProperty,
          new AuthenticatorImpl(attestedCredentialData(), new NoneAttestationStatement(), 0L),
          null,
          false,
          true);
    }

    AuthenticationData webauthn4jVerify() {
      WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();
      AuthenticationData data =
          manager.parse(
              new AuthenticationRequest(
                  credId, null, authenticatorData, clientDataJsonBytes, signature));
      manager.verify(data, webauthn4jParams());
      return data;
    }
  }

  /** Builds a minimal COSE ES256 key map for the given EC public key. */
  private static byte[] buildEs256CoseKey(ECPublicKey pub) {
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1L, 2L); // kty = EC2
    m.put(3L, -7L); // alg = ES256
    m.put(-1L, 1L); // crv = P-256
    m.put(-2L, fixedBytes(pub.getW().getAffineX())); // x
    m.put(-3L, fixedBytes(pub.getW().getAffineY())); // y
    return CborTestEncoder.encodeMap(m);
  }

  /** Encodes a BigInteger as a 32-byte big-endian array (P-256 coordinate). */
  private static byte[] fixedBytes(BigInteger v) {
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
