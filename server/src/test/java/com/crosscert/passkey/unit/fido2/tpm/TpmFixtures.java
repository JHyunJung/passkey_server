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
