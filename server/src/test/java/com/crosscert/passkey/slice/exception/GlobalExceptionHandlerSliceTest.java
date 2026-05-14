package com.crosscert.passkey.slice.exception;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.crosscert.passkey.common.exception.BusinessException;
import com.crosscert.passkey.common.exception.ErrorCode;
import com.crosscert.passkey.common.exception.GlobalExceptionHandler;
import com.crosscert.passkey.common.filter.TraceIdFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@WebMvcTest(
    controllers = GlobalExceptionHandlerSliceTest.DummyController.class,
    excludeAutoConfiguration = {
      org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
      org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
    })
@Import({
  GlobalExceptionHandlerSliceTest.DummyController.class,
  GlobalExceptionHandler.class,
  TraceIdFilter.class // wired directly here so @WebMvcTest applies it to MockMvc
})
class GlobalExceptionHandlerSliceTest {

  @Autowired MockMvc mvc;
  @Autowired ObjectMapper objectMapper;

  // ---- BusinessException (4xx) ----
  @Test
  void business_exception_4xx_returns_envelope_with_code() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/tenant-not-found"))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.success").value(false))
        .andExpect(jsonPath("$.code").value("T001"))
        .andExpect(jsonPath("$.message").value("Tenant not found"))
        .andExpect(jsonPath("$.error.errorCode").value("T001"))
        .andExpect(jsonPath("$.traceId").exists())
        .andExpect(jsonPath("$.timestamp").exists());
  }

  // ---- BusinessException (5xx) ----
  @Test
  void business_exception_5xx_returns_500_envelope() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/internal"))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.success").value(false))
        .andExpect(jsonPath("$.code").value("C999"));
  }

  // ---- MethodArgumentNotValidException ----
  @Test
  void invalid_body_returns_400_with_field_errors() throws Exception {
    String body = objectMapper.writeValueAsString(new Payload("", 0));
    mvc.perform(
            post("/api/v1/rp/_dummy/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("C001"))
        .andExpect(jsonPath("$.error.fieldErrors").isArray())
        .andExpect(jsonPath("$.error.fieldErrors.length()").value(2));
  }

  // ---- MissingServletRequestParameterException ----
  @Test
  void missing_query_param_returns_400_c004() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/require-param"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("C004"));
  }

  // ---- MethodArgumentTypeMismatchException ----
  @Test
  void type_mismatch_returns_400_c005() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/typed-param").param("n", "not-a-number"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("C005"));
  }

  // ---- HttpMessageNotReadableException ----
  @Test
  void malformed_json_returns_400_c001() throws Exception {
    mvc.perform(
            post("/api/v1/rp/_dummy/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{not-json"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("C001"))
        .andExpect(jsonPath("$.message").value("Malformed JSON request"));
  }

  // ---- HttpRequestMethodNotSupportedException ----
  @Test
  void wrong_method_returns_405_c002() throws Exception {
    mvc.perform(post("/api/v1/rp/_dummy/typed-param"))
        .andExpect(status().isMethodNotAllowed())
        .andExpect(jsonPath("$.code").value("C002"));
  }

  // ---- AccessDeniedException ----
  @Test
  void access_denied_returns_403_a002() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/forbidden"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("A002"));
  }

  // ---- DataIntegrityViolationException ----
  @Test
  void data_integrity_returns_409_t004() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/duplicate"))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("T004"));
  }

  // ---- Fallback Exception ----
  @Test
  void unexpected_exception_returns_500_c999() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/boom"))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.code").value("C999"));
  }

  // ---- X-Trace-Id echo ----
  @Test
  void trace_id_header_is_echoed_when_provided() throws Exception {
    mvc.perform(get("/api/v1/rp/_dummy/ok").header("X-Trace-Id", "test-trace-123"))
        .andExpect(status().isOk())
        .andExpect(
            (result) -> {
              String header = result.getResponse().getHeader("X-Trace-Id");
              if (header == null || !header.equals("test-trace-123")) {
                throw new AssertionError("Expected X-Trace-Id echo, got: " + header);
              }
            });
  }

  // ---- Payload + DummyController ----
  record Payload(@NotBlank String name, @Min(1) int age) {}

  @RestController
  @RequestMapping("/api/v1/rp/_dummy")
  static class DummyController {

    @GetMapping("/tenant-not-found")
    public void tenantNotFound() {
      throw new BusinessException(ErrorCode.TENANT_NOT_FOUND);
    }

    @GetMapping("/internal")
    public void internal() {
      throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    @PostMapping("/validate")
    public String validate(@Valid @RequestBody Payload p) {
      return "ok";
    }

    @GetMapping("/require-param")
    public String requireParam(@RequestParam("q") String q) {
      return q;
    }

    @GetMapping("/typed-param")
    public int typedParam(@RequestParam("n") int n) {
      return n;
    }

    @GetMapping("/forbidden")
    public void forbidden() {
      throw new AccessDeniedException("nope");
    }

    @GetMapping("/duplicate")
    public void duplicate() {
      throw new DataIntegrityViolationException("uk_violation");
    }

    @GetMapping("/boom")
    public void boom() {
      throw new RuntimeException("kaboom");
    }

    @GetMapping("/ok")
    public String ok() {
      return "ok";
    }
  }
}
