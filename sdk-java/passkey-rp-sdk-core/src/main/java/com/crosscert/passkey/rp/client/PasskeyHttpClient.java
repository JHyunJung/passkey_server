package com.crosscert.passkey.rp.client;

import com.fasterxml.jackson.core.type.TypeReference;
import java.util.Map;

/**
 * Low-level HTTP abstraction used by {@link DefaultPasskeyClient}. Implementations handle the
 * envelope unwrapping ({@code ApiResponse<T>}) and error translation so call sites only ever see
 * the inner {@code T} or a typed exception.
 */
public interface PasskeyHttpClient {

  <T> T get(String path, Map<String, String> query, String apiKey, TypeReference<T> dataType);

  <T> T post(String path, Object body, String apiKey, TypeReference<T> dataType);

  <T> T patch(String path, Object body, String apiKey, TypeReference<T> dataType);

  void delete(String path, Map<String, String> query, String apiKey);
}
