package com.crosscert.passkey.fido2.cose;

import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cbor.CborDecoder;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
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
    assertOnP256Curve(x, y);
    ECPoint point = new ECPoint(x, y);
    try {
      java.security.AlgorithmParameters params =
          java.security.AlgorithmParameters.getInstance("EC");
      params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
      ECPublicKeySpec spec = new ECPublicKeySpec(point, ecSpec);
      return KeyFactory.getInstance("EC").generatePublic(spec);
    } catch (CoseException e) {
      throw e;
    } catch (Exception e) {
      throw new CoseException("failed to build EC public key", e);
    }
  }

  /**
   * Validates that the point (x, y) lies on the P-256 curve. The SunEC provider does not perform
   * point-on-curve validation when building a public key for signature verification, so an
   * authenticator could otherwise smuggle an off-curve point past registration (invalid curve
   * attack). Checks coordinate range, rejects the point at infinity, and verifies the curve
   * equation y² ≡ x³ + ax + b (mod p).
   *
   * <p>Shared with {@code fido2.tpm.TpmtPublic} for defense-in-depth validation of ECC coordinates
   * parsed from TPMT_PUBLIC structures.
   */
  public static void assertOnP256Curve(BigInteger x, BigInteger y) {
    ECParameterSpec ecSpec;
    try {
      java.security.AlgorithmParameters params =
          java.security.AlgorithmParameters.getInstance("EC");
      params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
      ecSpec = params.getParameterSpec(ECParameterSpec.class);
    } catch (Exception e) {
      throw new CoseException("failed to obtain P-256 parameters", e);
    }
    if (x.signum() == 0 && y.signum() == 0) {
      throw new CoseException("EC public key is the point at infinity");
    }
    EllipticCurve curve = ecSpec.getCurve();
    BigInteger p = ((ECFieldFp) curve.getField()).getP();
    if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
      throw new CoseException("EC public key coordinate out of field range");
    }
    BigInteger a = curve.getA();
    BigInteger b = curve.getB();
    BigInteger lhs = y.multiply(y).mod(p);
    BigInteger rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
    if (!lhs.equals(rhs)) {
      throw new CoseException("EC public key point is not on the P-256 curve");
    }
  }

  private static PublicKey parseRsa(Map<?, ?> map) {
    BigInteger n = new BigInteger(1, asBytes(map.get(-1L), "n"));
    BigInteger e = new BigInteger(1, asBytes(map.get(-2L), "e"));
    int bitLength = n.bitLength();
    if (bitLength < 2048 || bitLength > 8192) {
      throw new CoseException("RSA modulus size out of range: " + bitLength + " bits");
    }
    if (e.compareTo(BigInteger.valueOf(3)) < 0 || !e.testBit(0)) {
      throw new CoseException("RSA public exponent is invalid");
    }
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
