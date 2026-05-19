package com.crosscert.passkey.auth.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public JWKS endpoint. Returns every RSA public key currently configured for verification (the
 * primary key plus the previous key while rotation is in progress). RPs cache this and verify
 * locally — they pick the key whose {@code kid} matches the token header.
 *
 * <p>When the server runs in HS256 mode and no RSA keypair is configured the response is an empty
 * key set. This is a valid JWKS document; clients should fall back to other verification means.
 */
@RestController
public class JwksController {

  private static final String JWK_SET_MEDIA_TYPE = "application/jwk-set+json";

  private final TokenService tokenService;

  public JwksController(TokenService tokenService) {
    this.tokenService = tokenService;
  }

  @GetMapping(value = "/.well-known/jwks.json", produces = JWK_SET_MEDIA_TYPE)
  public ResponseEntity<Map<String, Object>> jwks() {
    Map<String, RSAPublicKey> keys = tokenService.rsaPublicKeysByKid();
    List<JWK> jwks = new ArrayList<>(keys.size());
    for (Map.Entry<String, RSAPublicKey> e : keys.entrySet()) {
      jwks.add(
          new RSAKey.Builder(e.getValue())
              .keyID(e.getKey())
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.RS256)
              .build()
              .toPublicJWK());
    }
    return ResponseEntity.ok()
        .cacheControl(CacheControl.maxAge(java.time.Duration.ofHours(1)).mustRevalidate())
        .contentType(MediaType.parseMediaType(JWK_SET_MEDIA_TYPE))
        .body(new JWKSet(jwks).toJSONObject(true));
  }
}
