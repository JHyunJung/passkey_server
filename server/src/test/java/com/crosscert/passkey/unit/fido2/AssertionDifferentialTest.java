package com.crosscert.passkey.unit.fido2;

import static org.assertj.core.api.Assertions.assertThat;

import com.crosscert.passkey.fido2.AuthenticationVerificationRequest;
import com.crosscert.passkey.fido2.AuthenticationVerificationResult;
import com.crosscert.passkey.fido2.AuthenticationVerifier;
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
 * {@link WebAuthnManager} produce identical results for the same well-formed assertion.
 *
 * <p>This test uses a real EC P-256 key pair and a real ECDSA signature to ensure both
 * implementations agree on {@code signCount} and {@code userVerified} (UV flag).
 */
class AssertionDifferentialTest {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  @Test
  void self_core_and_webauthn4j_agree_on_valid_assertion() throws Exception {
    // ── 1. Generate a real EC P-256 key pair ──────────────────────────────────
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair keyPair = gen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();

    // ── 2. Build storedCoseKeyBytes (AttestedCredentialData serialized form) ──
    // Format: aaguid(16) + credIdLen(2) + credId + COSE key map
    byte[] coseKeyMap = buildEs256CoseKey(pub);
    byte[] credId = new byte[] {0x01, 0x02, 0x03, 0x04};
    ByteArrayOutputStream acdOut = new ByteArrayOutputStream();
    acdOut.writeBytes(new byte[16]); // aaguid (zeros)
    acdOut.write((credId.length >> 8) & 0xff);
    acdOut.write(credId.length & 0xff);
    acdOut.writeBytes(credId);
    acdOut.writeBytes(coseKeyMap);
    byte[] storedCoseKeyBytes = acdOut.toByteArray();

    // ── 3. Build authenticatorData ────────────────────────────────────────────
    // rpIdHash(32) + flags(1) + signCount(4)
    String rpId = "example.com";
    String origin = "https://example.com";
    byte[] rpIdHash =
        MessageDigest.getInstance("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream adOut = new ByteArrayOutputStream();
    adOut.writeBytes(rpIdHash);
    int flags = 0x01 | 0x04; // UP=1, UV=1
    adOut.write(flags);
    adOut.writeBytes(new byte[] {0, 0, 0, 42}); // signCount = 42
    byte[] authenticatorData = adOut.toByteArray();

    // ── 4. Build clientDataJSON ────────────────────────────────────────────────
    byte[] challengeBytes = "test-challenge-bytes".getBytes(StandardCharsets.UTF_8);
    String clientDataJson =
        "{\"type\":\"webauthn.get\",\"challenge\":\""
            + B64URL.encodeToString(challengeBytes)
            + "\",\"origin\":\""
            + origin
            + "\"}";
    byte[] clientDataJsonBytes = clientDataJson.getBytes(StandardCharsets.UTF_8);

    // ── 5. Sign authData || SHA-256(clientDataJSON) ───────────────────────────
    byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJsonBytes);
    ByteArrayOutputStream signedData = new ByteArrayOutputStream();
    signedData.writeBytes(authenticatorData);
    signedData.writeBytes(clientDataHash);
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(keyPair.getPrivate());
    signer.update(signedData.toByteArray());
    byte[] signature = signer.sign();

    // ── 6. Run self-core AuthenticationVerifier ───────────────────────────────
    AuthenticationVerificationRequest selfReq =
        new AuthenticationVerificationRequest(
            authenticatorData,
            clientDataJsonBytes,
            signature,
            challengeBytes,
            List.of(origin),
            rpId,
            storedCoseKeyBytes,
            false);
    AuthenticationVerificationResult selfResult = new AuthenticationVerifier().verify(selfReq);

    // ── 7. Run webauthn4j WebAuthnManager ─────────────────────────────────────
    WebAuthnManager w4jManager = WebAuthnManager.createNonStrictWebAuthnManager();
    ObjectConverter objectConverter = new ObjectConverter();
    AttestedCredentialDataConverter conv = new AttestedCredentialDataConverter(objectConverter);

    AuthenticationRequest w4jAuthnReq =
        new AuthenticationRequest(
            credId,
            null, // userHandle
            authenticatorData,
            clientDataJsonBytes,
            signature);
    ServerProperty serverProperty =
        new ServerProperty(Set.of(new Origin(origin)), rpId, new DefaultChallenge(challengeBytes));
    AuthenticationParameters w4jParams =
        new AuthenticationParameters(
            serverProperty,
            new AuthenticatorImpl(
                conv.convert(storedCoseKeyBytes), new NoneAttestationStatement(), 0L),
            null,
            false,
            true);
    AuthenticationData w4jData = w4jManager.parse(w4jAuthnReq);
    w4jManager.verify(w4jData, w4jParams);

    long w4jSignCount = w4jData.getAuthenticatorData().getSignCount();
    boolean w4jUv = w4jData.getAuthenticatorData().isFlagUV();

    // ── 8. Assert both implementations agree ─────────────────────────────────
    assertThat(selfResult.newSignCount())
        .as("signCount: self-core vs webauthn4j")
        .isEqualTo(w4jSignCount);
    assertThat(selfResult.userVerified())
        .as("userVerified: self-core vs webauthn4j")
        .isEqualTo(w4jUv);

    // Sanity-check expected values
    assertThat(selfResult.newSignCount()).isEqualTo(42L);
    assertThat(selfResult.userVerified()).isTrue();
  }

  /**
   * Builds a minimal COSE ES256 key map for the given EC public key. Uses {@link CborTestEncoder}
   * which lives in the same test package.
   */
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
