package com.crosscert.passkey.rp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;

/** Test helper — RSA keypair + JWKS + access-token issue. */
public final class RsaTestKeys {

  public final RSAPublicKey publicKey;
  public final RSAPrivateKey privateKey;
  public final String kid;

  public RsaTestKeys(String kid) {
    try {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      KeyPair kp = gen.generateKeyPair();
      this.publicKey = (RSAPublicKey) kp.getPublic();
      this.privateKey = (RSAPrivateKey) kp.getPrivate();
      this.kid = kid;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public String jwksJson() {
    RSAKey jwk =
        new RSAKey.Builder(publicKey)
            .keyID(kid)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .build()
            .toPublicJWK();
    return new JWKSet(List.of(jwk)).toString();
  }

  public String issueAccess(String issuer, String tid, String sub, String xuid, Date exp)
      throws JOSEException {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(sub)
            .claim("tid", tid)
            .claim("xuid", xuid)
            .claim("typ", "access")
            .issueTime(new Date())
            .expirationTime(exp)
            .build();
    SignedJWT signed =
        new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(), claims);
    signed.sign(new RSASSASigner(privateKey));
    return signed.serialize();
  }
}
