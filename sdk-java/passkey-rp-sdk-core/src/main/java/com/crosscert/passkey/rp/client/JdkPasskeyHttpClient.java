package com.crosscert.passkey.rp.client;

import com.crosscert.passkey.rp.dto.ApiResponse;
import com.crosscert.passkey.rp.error.ErrorTranslator;
import com.crosscert.passkey.rp.error.PasskeyApiException;
import com.crosscert.passkey.rp.error.PasskeyTransportException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * {@link PasskeyHttpClient} backed by the JDK 11+ {@code java.net.http.HttpClient}. Zero transitive
 * dependencies. Handles JSON serialisation, envelope unwrapping, retries, and trace-id propagation.
 */
public final class JdkPasskeyHttpClient implements PasskeyHttpClient {

  private static final Logger log = LoggerFactory.getLogger(JdkPasskeyHttpClient.class);
  private static final String TRACE_HEADER = "X-Trace-Id";
  private static final String API_KEY_HEADER = "X-API-Key";
  private static final String CONTENT_TYPE = "application/json";

  private final HttpClient http;
  private final ObjectMapper mapper;
  private final URI baseUrl;
  private final Duration readTimeout;
  private final RetryPolicy retry;
  private final Random rng = new Random();

  public JdkPasskeyHttpClient(
      URI baseUrl, Duration connectTimeout, Duration readTimeout, RetryPolicy retry) {
    this.baseUrl = stripTrailingSlash(baseUrl);
    this.readTimeout = readTimeout;
    this.retry = retry;
    this.http = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
    this.mapper =
        new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
  }

  /** Visible for tests so they can stub a mock {@link HttpClient}. */
  JdkPasskeyHttpClient(HttpClient http, URI baseUrl, Duration readTimeout, RetryPolicy retry) {
    this.http = http;
    this.baseUrl = stripTrailingSlash(baseUrl);
    this.readTimeout = readTimeout;
    this.retry = retry;
    this.mapper =
        new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
  }

  @Override
  public <T> T get(String path, Map<String, String> query, String apiKey, TypeReference<T> data) {
    return execute(builder(path, query, apiKey).GET(), data);
  }

  @Override
  public <T> T post(String path, Object body, String apiKey, TypeReference<T> data) {
    return execute(builder(path, null, apiKey).POST(jsonBody(body)), data);
  }

  @Override
  public <T> T patch(String path, Object body, String apiKey, TypeReference<T> data) {
    return execute(builder(path, null, apiKey).method("PATCH", jsonBody(body)), data);
  }

  @Override
  public void delete(String path, Map<String, String> query, String apiKey) {
    execute(builder(path, query, apiKey).DELETE(), new TypeReference<Void>() {});
  }

  private HttpRequest.Builder builder(String path, Map<String, String> query, String apiKey) {
    URI uri = URI.create(baseUrl + path + buildQuery(query));
    HttpRequest.Builder b =
        HttpRequest.newBuilder(uri)
            .timeout(readTimeout)
            .header("Accept", CONTENT_TYPE)
            .header("Content-Type", CONTENT_TYPE)
            .header(API_KEY_HEADER, apiKey);
    String traceId = MDC.get("traceId");
    if (traceId != null) {
      b.header(TRACE_HEADER, traceId);
    }
    return b;
  }

  private HttpRequest.BodyPublisher jsonBody(Object body) {
    if (body == null) return BodyPublishers.noBody();
    try {
      return BodyPublishers.ofString(mapper.writeValueAsString(body), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new PasskeyTransportException("serialise body", e);
    }
  }

  private <T> T execute(HttpRequest.Builder builder, TypeReference<T> dataType) {
    HttpRequest req = builder.build();
    IOException last = null;
    for (int attempt = 0; attempt <= retry.maxRetries(); attempt++) {
      try {
        HttpResponse<String> res = http.send(req, BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (shouldRetry(res, attempt)) {
          sleep(backoffFor(res, attempt));
          continue;
        }
        return handleResponse(res, dataType);
      } catch (IOException e) {
        last = e;
        if (attempt == retry.maxRetries()) break;
        sleep(retry.backoffFor(attempt, rng));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new PasskeyTransportException("interrupted", e);
      }
    }
    throw new PasskeyTransportException("transport failed after retries", last);
  }

  private boolean shouldRetry(HttpResponse<String> res, int attempt) {
    if (attempt >= retry.maxRetries()) return false;
    int sc = res.statusCode();
    return sc == 429 || (sc >= 500 && sc <= 599);
  }

  private Duration backoffFor(HttpResponse<String> res, int attempt) {
    if (res.statusCode() == 429) {
      Optional<String> ra = res.headers().firstValue("Retry-After");
      if (ra.isPresent()) {
        try {
          return Duration.ofSeconds(Long.parseLong(ra.get().trim()));
        } catch (NumberFormatException ignored) {
          // HTTP-date variant — fall back to backoff.
        }
      }
    }
    return retry.backoffFor(attempt, rng);
  }

  @SuppressWarnings("unchecked")
  private <T> T handleResponse(HttpResponse<String> res, TypeReference<T> dataType) {
    int sc = res.statusCode();
    String body = res.body();
    ApiResponse<Object> envelope = parseEnvelope(body, dataType);
    if (sc >= 200 && sc < 300 && envelope.success()) {
      if (dataType.getType() == Void.class) return null;
      return (T) envelope.data();
    }
    Duration retryAfter =
        res.headers()
            .firstValue("Retry-After")
            .flatMap(JdkPasskeyHttpClient::parseRetryAfterSeconds)
            .orElse(null);
    PasskeyApiException ex = ErrorTranslator.translate(envelope, sc, retryAfter);
    log.warn(
        "passkey.http.error status={} code={} traceId={} message={}",
        sc,
        ex.rawCode(),
        ex.traceId(),
        ex.getMessage());
    throw ex;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private <T> ApiResponse<Object> parseEnvelope(String body, TypeReference<T> dataType) {
    if (body == null || body.isBlank()) {
      throw new PasskeyTransportException("empty response body", null);
    }
    try {
      JavaType inner = mapper.getTypeFactory().constructType(dataType.getType());
      JavaType envelope = mapper.getTypeFactory().constructParametricType(ApiResponse.class, inner);
      return mapper.readValue(body, envelope);
    } catch (IOException e) {
      throw new PasskeyTransportException("malformed response envelope: " + body, e);
    }
  }

  private static Optional<Duration> parseRetryAfterSeconds(String value) {
    try {
      return Optional.of(Duration.ofSeconds(Long.parseLong(value.trim())));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  private static String buildQuery(Map<String, String> query) {
    if (query == null || query.isEmpty()) return "";
    StringBuilder sb = new StringBuilder("?");
    boolean first = true;
    for (Map.Entry<String, String> e : query.entrySet()) {
      if (e.getValue() == null) continue;
      if (!first) sb.append('&');
      sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
          .append('=')
          .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
      first = false;
    }
    return sb.length() == 1 ? "" : sb.toString();
  }

  private static URI stripTrailingSlash(URI uri) {
    String s = uri.toString();
    return URI.create(s.endsWith("/") ? s.substring(0, s.length() - 1) : s);
  }

  private static void sleep(Duration d) {
    try {
      Thread.sleep(d.toMillis());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new UncheckedIOException(new IOException("sleep interrupted", e));
    }
  }
}
