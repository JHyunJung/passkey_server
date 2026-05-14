package com.crosscert.passkey.auth.apikey.service;

import com.crosscert.passkey.auth.apikey.domain.ApiKey;
import com.crosscert.passkey.auth.apikey.repository.ApiKeyRepository;
import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

  private static final SecureRandom RNG = new SecureRandom();
  private static final String KEY_VERSION = "pk";
  private static final int PREFIX_BYTES = 6;
  private static final int SECRET_BYTES = 32;

  private final ApiKeyRepository repo;
  private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

  public record IssuedKey(UUID id, String plaintext, String prefix) {}

  @Transactional
  public IssuedKey issue(UUID tenantId, String name) {
    String prefix = randomBase64Url(PREFIX_BYTES);
    String secret = randomBase64Url(SECRET_BYTES);
    String plaintext = KEY_VERSION + "_" + prefix + "." + secret;
    String secretHash = argon2.hash(2, 65_536, 1, secret.toCharArray());

    ApiKey saved = repo.save(ApiKey.create(tenantId, prefix, secretHash, name));
    return new IssuedKey(saved.getId(), plaintext, prefix);
  }

  /** Returns the resolved (tenantId, apiKeyId) or empty if verification fails. */
  @Transactional
  public Optional<ResolvedKey> verify(String presented) {
    if (presented == null || !presented.startsWith(KEY_VERSION + "_")) {
      return Optional.empty();
    }
    String body = presented.substring(KEY_VERSION.length() + 1);
    int dot = body.indexOf('.');
    if (dot < 0) {
      return Optional.empty();
    }
    String prefix = body.substring(0, dot);
    String secret = body.substring(dot + 1);

    Optional<ApiKey> found = repo.findByPrefix(prefix);
    if (found.isEmpty()) {
      return Optional.empty();
    }
    ApiKey k = found.get();
    if (!k.isActive()) {
      throw new BusinessException(ErrorCode.INVALID_API_KEY);
    }
    if (!argon2.verify(k.getSecretHash(), secret.toCharArray())) {
      return Optional.empty();
    }
    k.recordUse();
    return Optional.of(new ResolvedKey(k.getTenantId(), k.getId()));
  }

  public record ResolvedKey(UUID tenantId, UUID apiKeyId) {}

  private static String randomBase64Url(int bytes) {
    byte[] buf = new byte[bytes];
    RNG.nextBytes(buf);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
  }
}
