package com.crosscert.passkey.credential.webauthn;

import java.util.Base64;

public final class Base64UrlCodec {

  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

  private Base64UrlCodec() {}

  public static String encode(byte[] bytes) {
    return ENCODER.encodeToString(bytes);
  }

  public static byte[] decode(String s) {
    return DECODER.decode(s);
  }
}
