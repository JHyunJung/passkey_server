package com.crosscert.passkey.unit.auth.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/** Generates an in-memory RSA 2048 keypair and exposes the PEMs the way JwtProperties expects. */
final class RsaTestKeys {

  final String privatePem;
  final String publicPem;
  final KeyPair keyPair;

  private RsaTestKeys(KeyPair kp) {
    this.keyPair = kp;
    this.privatePem = pem("PRIVATE KEY", kp.getPrivate().getEncoded());
    this.publicPem = pem("PUBLIC KEY", kp.getPublic().getEncoded());
  }

  static RsaTestKeys generate() {
    try {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      return new RsaTestKeys(gen.generateKeyPair());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String pem(String label, byte[] der) {
    String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
    return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
  }
}
