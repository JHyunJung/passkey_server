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
    AuthenticationVerificationResult result = new AuthenticationVerifier().verify(f.request(true));
    assertThat(result.newSignCount()).isEqualTo(7L);
    assertThat(result.userVerified()).isTrue();
  }

  @Test
  void rejects_challenge_mismatch() throws Exception {
    Fixture f = new Fixture("https://example.com", "example.com", true, true);
    AuthenticationVerificationRequest req =
        f.requestWithChallenge("d3JvbmctY2hhbGxlbmdl".getBytes());
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
          authData,
          clientDataJson,
          sign(true),
          expected,
          List.of("https://example.com"),
          rpId,
          coseKey,
          false);
    }

    AuthenticationVerificationRequest requestUvRequired() throws Exception {
      return build(challenge, true, true);
    }

    private AuthenticationVerificationRequest build(
        byte[] expectedChallenge, boolean uvRequired, boolean validSignature) throws Exception {
      return new AuthenticationVerificationRequest(
          authData,
          clientDataJson,
          sign(validSignature),
          expectedChallenge,
          List.of("https://example.com"),
          rpId,
          coseKey,
          uvRequired);
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

    // AttestedCredentialData serialized form: aaguid(16) + credIdLen(2) + credId + coseKey.
    // This matches the credential.public_key_cose column the verifier reads via
    // AttestedCredentialData.parse().
    private static byte[] es256CoseKey(ECPublicKey pub) {
      Map<Object, Object> m = new LinkedHashMap<>();
      m.put(1L, 2L);
      m.put(3L, -7L);
      m.put(-1L, 1L);
      m.put(-2L, fixed(pub.getW().getAffineX()));
      m.put(-3L, fixed(pub.getW().getAffineY()));
      byte[] cose = CborTestEncoder.encodeMap(m);
      byte[] credId = new byte[] {1, 2, 3, 4};
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.writeBytes(new byte[16]); // aaguid
      out.write((credId.length >> 8) & 0xff);
      out.write(credId.length & 0xff);
      out.writeBytes(credId);
      out.writeBytes(cose);
      return out.toByteArray();
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
