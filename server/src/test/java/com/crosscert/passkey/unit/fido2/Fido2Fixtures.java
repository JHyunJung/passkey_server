package com.crosscert.passkey.unit.fido2;

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
import java.util.Map;

/**
 * Shared, self-consistent FIDO2 ceremony fixtures built from real EC P-256 keys. Used by the
 * verifier unit tests and the differential tests so the same authenticator output can be checked by
 * both the self-implemented core and webauthn4j.
 */
public final class Fido2Fixtures {

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private Fido2Fixtures() {}

  /** A complete registration ceremony's outputs plus the facts needed to assert against them. */
  public record Registration(
      byte[] attestationObject,
      byte[] clientDataJson,
      byte[] challenge,
      byte[] credentialId,
      long signCount) {}

  /**
   * Build a valid registration ceremony for the given attestation format ("none" or "packed"),
   * origin, and rpId. The attestationObject embeds a real ES256 COSE public key; for "packed" the
   * attStmt carries a real self-attestation signature.
   */
  public static Registration validRegistration(String fmt, String origin, String rpId)
      throws Exception {
    return buildRegistration(fmt, "webauthn.create", 0x45, origin, rpId);
  }

  /**
   * Build a registration ceremony whose clientDataJSON declares the given type (e.g. "webauthn.get"
   * to trigger a wrong-ceremony-type rejection). Attestation format is "none".
   */
  public static Registration registrationWithClientType(String type, String origin, String rpId)
      throws Exception {
    return buildRegistration("none", type, 0x45, origin, rpId);
  }

  /**
   * Build a registration ceremony whose authenticator-data flags byte is set explicitly. Use to
   * exercise UP/UV/AT rejection paths. Attestation format is "none".
   */
  public static Registration registrationWithFlags(int flags, String origin, String rpId)
      throws Exception {
    return buildRegistration("none", "webauthn.create", flags, origin, rpId);
  }

  private static Registration buildRegistration(
      String fmt, String clientType, int flags, String origin, String rpId) throws Exception {
    // 1. Fixed challenge bytes.
    byte[] challenge = "Y2hhbGxlbmdl".getBytes(StandardCharsets.UTF_8);

    // 2. EC P-256 key pair.
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = gen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) pair.getPublic();

    // 3. COSE_Key CBOR: kty=2, alg=-7, crv=1, x(32), y(32).
    Map<Object, Object> coseMap = new LinkedHashMap<>();
    coseMap.put(1L, 2L);
    coseMap.put(3L, -7L);
    coseMap.put(-1L, 1L);
    coseMap.put(-2L, coordinate(pub.getW().getAffineX()));
    coseMap.put(-3L, coordinate(pub.getW().getAffineY()));
    byte[] coseKeyBytes = CborTestEncoder.encodeMap(coseMap);

    // 4. Authenticator data: rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) |
    //    credIdLen(2) | credId(4) | coseKey.
    byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
    byte[] aaguid = new byte[16]; // all-zeros AAGUID
    byte[] credId = new byte[] {1, 2, 3, 4};
    long signCount = 0L;

    ByteArrayOutputStream authDataOut = new ByteArrayOutputStream();
    authDataOut.writeBytes(rpIdHash); // 32 bytes
    authDataOut.write(flags & 0xff); // e.g. UP(0x01) | UV(0x04) | AT(0x40) = 0x45
    authDataOut.write((int) ((signCount >> 24) & 0xff));
    authDataOut.write((int) ((signCount >> 16) & 0xff));
    authDataOut.write((int) ((signCount >> 8) & 0xff));
    authDataOut.write((int) (signCount & 0xff));
    authDataOut.writeBytes(aaguid); // 16 bytes
    authDataOut.write((credId.length >> 8) & 0xff);
    authDataOut.write(credId.length & 0xff);
    authDataOut.writeBytes(credId);
    authDataOut.writeBytes(coseKeyBytes);
    byte[] authDataBytes = authDataOut.toByteArray();

    // 5. clientDataJSON.
    String challengeB64 = B64URL.encodeToString(challenge);
    String clientDataStr =
        "{\"type\":\""
            + clientType
            + "\",\"challenge\":\""
            + challengeB64
            + "\",\"origin\":\""
            + origin
            + "\"}";
    byte[] clientDataJson = clientDataStr.getBytes(StandardCharsets.UTF_8);

    // 6. attStmt.
    Map<Object, Object> attStmt;
    if ("packed".equals(fmt)) {
      byte[] clientDataHash = sha256(clientDataJson);
      ByteArrayOutputStream signedData = new ByteArrayOutputStream();
      signedData.writeBytes(authDataBytes);
      signedData.writeBytes(clientDataHash);

      Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(pair.getPrivate());
      signer.update(signedData.toByteArray());
      byte[] sig = signer.sign();

      attStmt = new LinkedHashMap<>();
      attStmt.put("alg", -7L);
      attStmt.put("sig", sig);
    } else {
      // "none" — empty map.
      attStmt = new LinkedHashMap<>();
    }

    // 7. attestationObject CBOR map: {fmt, attStmt, authData}.
    Map<Object, Object> aoMap = new LinkedHashMap<>();
    aoMap.put("fmt", fmt);
    aoMap.put("attStmt", attStmt);
    aoMap.put("authData", authDataBytes);
    byte[] attestationObject = CborTestEncoder.encodeMap(aoMap);

    return new Registration(attestationObject, clientDataJson, challenge, credId, signCount);
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static byte[] coordinate(BigInteger v) {
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
