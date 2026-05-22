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
 * A COSE_Key (RFC 8152) decoded into a JCA {@link PublicKey}. Only the two algorithms registered in
 * the WebAuthn registration options are supported in Milestone A:
 *
 * <ul>
 *   <li>ES256 (alg -7): EC2 key on the P-256 curve.
 *   <li>RS256 (alg -257): RSA key.
 * </ul>
 *
 * <p>The COSE label constants follow RFC 8152 §7: 1=kty, 3=alg; for EC2 -1=crv, -2=x, -3=y; for RSA
 * -1=n, -2=e.
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
