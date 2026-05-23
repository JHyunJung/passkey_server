package com.crosscert.passkey.unit.fido2.tpm;

import java.nio.ByteBuffer;

final class TpmFixtures {
  private TpmFixtures() {}

  /** Build a minimal valid TPMS_ATTEST (TPM_ST_ATTEST_CERTIFY) for testing. */
  static byte[] attestCertify(byte[] extraData, byte[] attestedName) {
    // magic(4) + type(2) + qSignerLen(2)=0 + extraLen(2)+extra + clock(17) + fwVer(8)
    //   + nameLen(2)+name + qNameLen(2)=0
    int len = 4 + 2 + 2 + 2 + extraData.length + 17 + 8 + 2 + attestedName.length + 2;
    ByteBuffer buf = ByteBuffer.allocate(len);
    buf.putInt(0xFF544347); // magic
    buf.putShort((short) 0x8017); // type CERTIFY
    buf.putShort((short) 0); // qualifiedSigner empty
    buf.putShort((short) extraData.length);
    buf.put(extraData);
    buf.put(new byte[17]); // clockInfo (don't care)
    buf.putLong(0L); // firmwareVersion
    buf.putShort((short) attestedName.length);
    buf.put(attestedName);
    buf.putShort((short) 0); // qualifiedName empty
    return buf.array();
  }

  /** Build a minimal TPMT_PUBLIC for ECC P-256. */
  static byte[] publicEccP256(byte[] x, byte[] y) {
    // type(2)=0x0023 + nameAlg(2)=0x000B + objectAttributes(4) + authPolicy len(2)=0
    //   + parameters: symmetric(2)=0x0010 NULL + scheme(2)=0x0010 NULL + curveId(2)=0x0003 P-256
    //     + kdf(2)=0x0010 NULL
    //   + unique TPMS_ECC_POINT: x sized + y sized
    int paramsLen = 2 + 2 + 2 + 2;
    int len = 2 + 2 + 4 + 2 + paramsLen + 2 + x.length + 2 + y.length;
    ByteBuffer buf = ByteBuffer.allocate(len);
    buf.putShort((short) 0x0023); // TPM_ALG_ECC
    buf.putShort((short) 0x000B); // TPM_ALG_SHA256
    buf.putInt(0x00050072); // objectAttributes
    buf.putShort((short) 0); // authPolicy empty
    buf.putShort((short) 0x0010); // symmetric NULL
    buf.putShort((short) 0x0010); // scheme NULL
    buf.putShort((short) 0x0003); // curveId P-256
    buf.putShort((short) 0x0010); // kdf NULL
    buf.putShort((short) x.length);
    buf.put(x);
    buf.putShort((short) y.length);
    buf.put(y);
    return buf.array();
  }

  /**
   * Build a TPMT_PUBLIC for ECC with a non-P-256 curve id (for negative tests). curveId offset:
   * type(2)+nameAlg(2)+objAttr(4)+authPolicyLen(2)+sym(2)+scheme(2) = 14.
   */
  static byte[] publicEccWithCurve(int curveId, byte[] x, byte[] y) {
    byte[] base = publicEccP256(x, y);
    ByteBuffer.wrap(base).putShort(14, (short) curveId);
    return base;
  }

  /** Build a minimal TPMT_PUBLIC for RSA 2048. */
  static byte[] publicRsa2048(byte[] modulus) {
    int paramsLen = 2 + 2 + 2 + 4;
    int len = 2 + 2 + 4 + 2 + paramsLen + 2 + modulus.length;
    ByteBuffer buf = ByteBuffer.allocate(len);
    buf.putShort((short) 0x0001); // TPM_ALG_RSA
    buf.putShort((short) 0x000B); // TPM_ALG_SHA256
    buf.putInt(0x00050072); // objectAttributes
    buf.putShort((short) 0); // authPolicy empty
    buf.putShort((short) 0x0010); // symmetric NULL
    buf.putShort((short) 0x0010); // scheme NULL
    buf.putShort((short) 2048); // keyBits
    buf.putInt(0x00010001); // exponent = 65537
    buf.putShort((short) modulus.length);
    buf.put(modulus);
    return buf.array();
  }
}
