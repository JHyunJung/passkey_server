# Spring Boot API Response Template

> Spring Boot 3.x + Java 17+ 기반의 통합 API 응답 표준 템플릿

## 목차

1. [개요](#개요)
2. [설계 원칙](#설계-원칙)
3. [패키지 구조](#패키지-구조)
4. [구성 요소](#구성-요소)
   - [ApiResponse](#1-apiresponset)
   - [ErrorDetail / FieldError](#2-errordetail--fielderror)
   - [ErrorCode](#3-errorcode)
   - [BusinessException](#4-businessexception)
   - [GlobalExceptionHandler](#5-globalexceptionhandler)
   - [PageResponse](#6-pageresponset)
   - [TraceIdFilter](#7-traceidfilter)
5. [Controller 사용 예시](#controller-사용-예시)
6. [로깅 설정](#로깅-설정)
7. [의존성](#의존성)
8. [응답 예시](#응답-예시)

---

## 개요

본 문서는 Spring Boot 기반 REST API에서 사용할 **통합 응답 포맷 템플릿**을 정의한다. 성공/실패 응답을 동일한 스키마로 통일하고, 에러 코드를 중앙에서 관리하며, 분산 환경에서의 추적성을 위해 traceId를 포함한다.

### 적용 대상

- Spring Boot 3.x
- Java 17+
- Jackson (기본 포함)
- Lombok
- SLF4J (MDC)

---

## 설계 원칙

| 원칙 | 설명 |
|------|------|
| **단일 스키마** | 성공/실패 응답 모두 동일한 `ApiResponse<T>` 구조 사용 |
| **이중 상태 관리** | HTTP Status는 전송 계층, `code`는 도메인 계층 의미 표현 |
| **단일 진실 공급원** | `ErrorCode` enum이 모든 에러의 중앙 저장소 |
| **깔끔한 페이로드** | `@JsonInclude(NON_NULL)`로 불필요한 null 필드 제거 |
| **추적 가능성** | 모든 응답에 `traceId`를 포함해 로그와 매칭 가능 |
| **불변성** | Java `record` 기반으로 불변 객체 보장 |

---

## 패키지 구조

```
com.example
├── common
│   ├── response
│   │   ├── ApiResponse.java
│   │   ├── ErrorDetail.java
│   │   ├── FieldError.java
│   │   └── PageResponse.java
│   ├── exception
│   │   ├── ErrorCode.java
│   │   ├── BusinessException.java
│   │   └── GlobalExceptionHandler.java
│   └── filter
│       └── TraceIdFilter.java
└── user
    ├── controller
    ├── service
    └── dto
```

---

## 구성 요소

### 1. `ApiResponse<T>`

통합 응답 래퍼. 모든 API 응답은 이 타입으로 감싸서 반환한다.

```java
package com.example.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.slf4j.MDC;

import java.time.LocalDateTime;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        boolean success,
        String code,
        String message,
        T data,
        ErrorDetail error,
        String traceId,
        LocalDateTime timestamp
) {
    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, "OK", "Success", data, null,
                MDC.get("traceId"), LocalDateTime.now());
    }

    public static <T> ApiResponse<T> ok(String message, T data) {
        return new ApiResponse<>(true, "OK", message, data, null,
                MDC.get("traceId"), LocalDateTime.now());
    }

    public static ApiResponse<Void> ok() {
        return new ApiResponse<>(true, "OK", "Success", null, null,
                MDC.get("traceId"), LocalDateTime.now());
    }

    public static ApiResponse<Void> error(ErrorCode code) {
        return new ApiResponse<>(false, code.getCode(), code.getMessage(), null,
                new ErrorDetail(code.getCode(), null),
                MDC.get("traceId"), LocalDateTime.now());
    }

    public static ApiResponse<Void> error(ErrorCode code, List<FieldError> fieldErrors) {
        return new ApiResponse<>(false, code.getCode(), code.getMessage(), null,
                new ErrorDetail(code.getCode(), fieldErrors),
                MDC.get("traceId"), LocalDateTime.now());
    }

    public static ApiResponse<Void> error(ErrorCode code, String detailMessage) {
        return new ApiResponse<>(false, code.getCode(), detailMessage, null,
                new ErrorDetail(code.getCode(), null),
                MDC.get("traceId"), LocalDateTime.now());
    }
}
```

---

### 2. `ErrorDetail` / `FieldError`

에러 상세 정보와 필드 단위 검증 실패 정보를 담는 객체.

**ErrorDetail.java**

```java
package com.example.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorDetail(
        String errorCode,
        List<FieldError> fieldErrors
) {}
```

**FieldError.java**

```java
package com.example.common.response;

public record FieldError(
        String field,
        Object rejectedValue,
        String reason
) {}
```

---

### 3. `ErrorCode`

모든 에러 코드의 중앙 저장소. HTTP Status, 코드, 메시지를 한 곳에서 관리한다.

```java
package com.example.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    // Common
    INVALID_INPUT(HttpStatus.BAD_REQUEST, "C001", "Invalid input value"),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "C002", "Method not allowed"),
    ENTITY_NOT_FOUND(HttpStatus.NOT_FOUND, "C003", "Entity not found"),
    MISSING_PARAMETER(HttpStatus.BAD_REQUEST, "C004", "Required parameter missing"),
    TYPE_MISMATCH(HttpStatus.BAD_REQUEST, "C005", "Type mismatch"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "C999", "Server error"),

    // Auth
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "A001", "Authentication required"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "A002", "Access denied"),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "A003", "Token expired"),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "A004", "Invalid token"),

    // Business
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "U001", "User not found"),
    DUPLICATE_EMAIL(HttpStatus.CONFLICT, "U002", "Email already exists");

    private final HttpStatus status;
    private final String code;
    private final String message;
}
```

#### 코드 체계 규칙

| Prefix | 의미 | 예시 |
|--------|------|------|
| `C` | Common (공통) | `C001`, `C999` |
| `A` | Auth (인증/인가) | `A001` ~ `A004` |
| `U` | User (도메인별) | `U001`, `U002` |

> 도메인별로 2자리 prefix + 3자리 숫자 조합으로 확장 가능.

---

### 4. `BusinessException`

비즈니스 로직에서 발생하는 예외. `ErrorCode`를 필수로 포함한다.

```java
package com.example.common.exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private final ErrorCode errorCode;

    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public BusinessException(ErrorCode errorCode, String detail) {
        super(detail);
        this.errorCode = errorCode;
    }
}
```

---

### 5. `GlobalExceptionHandler`

애플리케이션 전역의 예외를 처리하여 통일된 `ApiResponse` 포맷으로 변환한다.

```java
package com.example.common.exception;

import com.example.common.response.ApiResponse;
import com.example.common.response.FieldError;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.List;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBusiness(BusinessException e, HttpServletRequest req) {
        log.warn("[BusinessException] {} {} - {}", req.getMethod(), req.getRequestURI(), e.getMessage());
        ErrorCode code = e.getErrorCode();
        return ResponseEntity.status(code.getStatus())
                .body(ApiResponse.error(code, e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException e) {
        List<FieldError> errors = e.getBindingResult().getFieldErrors().stream()
                .map(fe -> new FieldError(fe.getField(), fe.getRejectedValue(), fe.getDefaultMessage()))
                .toList();
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.INVALID_INPUT, errors));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResponse<Void>> handleMissingParam(MissingServletRequestParameterException e) {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.MISSING_PARAMETER, e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponse<Void>> handleTypeMismatch(MethodArgumentTypeMismatchException e) {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.TYPE_MISMATCH, e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleNotReadable(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.INVALID_INPUT, "Malformed JSON request"));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodNotAllowed(HttpRequestMethodNotSupportedException e) {
        return ResponseEntity.status(ErrorCode.METHOD_NOT_ALLOWED.getStatus())
                .body(ApiResponse.error(ErrorCode.METHOD_NOT_ALLOWED, e.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied(AccessDeniedException e) {
        return ResponseEntity.status(ErrorCode.ACCESS_DENIED.getStatus())
                .body(ApiResponse.error(ErrorCode.ACCESS_DENIED));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleUnexpected(Exception e, HttpServletRequest req) {
        log.error("[Unhandled] {} {}", req.getMethod(), req.getRequestURI(), e);
        ErrorCode code = ErrorCode.INTERNAL_SERVER_ERROR;
        return ResponseEntity.status(code.getStatus()).body(ApiResponse.error(code));
    }
}
```

#### 처리 대상 예외 요약

| 예외 | HTTP Status | Error Code |
|------|-------------|------------|
| `BusinessException` | ErrorCode 기반 | ErrorCode 기반 |
| `MethodArgumentNotValidException` | 400 | `C001` |
| `MissingServletRequestParameterException` | 400 | `C004` |
| `MethodArgumentTypeMismatchException` | 400 | `C005` |
| `HttpMessageNotReadableException` | 400 | `C001` |
| `HttpRequestMethodNotSupportedException` | 405 | `C002` |
| `AccessDeniedException` | 403 | `A002` |
| `Exception` (Fallback) | 500 | `C999` |

---

### 6. `PageResponse<T>`

페이지네이션 결과를 Spring Data의 `Page<T>`에서 변환해 반환한다. 목록 API가 없다면 제외해도 무방하다.

```java
package com.example.common.response;

import org.springframework.data.domain.Page;

import java.util.List;

public record PageResponse<T>(
        List<T> content,
        int page,
        int size,
        long totalElements,
        int totalPages,
        boolean hasNext,
        boolean hasPrevious
) {
    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(
                page.getContent(),
                page.getNumber(),
                page.getSize(),
                page.getTotalElements(),
                page.getTotalPages(),
                page.hasNext(),
                page.hasPrevious()
        );
    }
}
```

---

### 7. `TraceIdFilter`

요청마다 고유 traceId를 부여하고 MDC에 저장해 응답 및 로그에서 추적할 수 있게 한다.

```java
package com.example.common.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceIdFilter extends OncePerRequestFilter {

    private static final String TRACE_ID_HEADER = "X-Trace-Id";
    private static final String MDC_KEY = "traceId";

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String traceId = Optional.ofNullable(req.getHeader(TRACE_ID_HEADER))
                .filter(s -> !s.isBlank())
                .orElseGet(() -> UUID.randomUUID().toString().replace("-", "").substring(0, 16));

        MDC.put(MDC_KEY, traceId);
        res.setHeader(TRACE_ID_HEADER, traceId);

        try {
            chain.doFilter(req, res);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
```

#### 동작 방식

1. 클라이언트 요청의 `X-Trace-Id` 헤더가 있으면 사용, 없으면 새로 생성
2. MDC에 저장해 로그 패턴 `%X{traceId}`에서 출력 가능
3. 응답 헤더 `X-Trace-Id`로도 반환해 클라이언트가 확인 가능
4. 요청 종료 시 MDC에서 제거 (메모리 누수 방지)

> MSA 환경에서는 Micrometer Tracing을 사용하는 것도 고려. 단일 서버에서는 본 Filter로 충분.

---

## Controller 사용 예시

```java
package com.example.user.controller;

import com.example.common.response.ApiResponse;
import com.example.common.response.PageResponse;
import com.example.user.dto.UserCreateRequest;
import com.example.user.dto.UserResponse;
import com.example.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/{id}")
    public ApiResponse<UserResponse> getUser(@PathVariable Long id) {
        return ApiResponse.ok(userService.findById(id));
    }

    @GetMapping
    public ApiResponse<PageResponse<UserResponse>> list(Pageable pageable) {
        return ApiResponse.ok(PageResponse.from(userService.findAll(pageable)));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResponse<UserResponse> create(@Valid @RequestBody UserCreateRequest req) {
        return ApiResponse.ok("User created", userService.create(req));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public ApiResponse<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return ApiResponse.ok();
    }
}
```

#### Service 예외 발생 예

```java
public UserResponse findById(Long id) {
    return userRepository.findById(id)
            .map(UserResponse::from)
            .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
}
```

---

## 로깅 설정

### logback-spring.xml

traceId를 로그 패턴에 포함해 응답과 서버 로그를 연결한다.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <property name="LOG_PATTERN"
              value="%d{yyyy-MM-dd HH:mm:ss.SSS} %-5level [%X{traceId:-}] %logger{36} - %msg%n"/>

    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>${LOG_PATTERN}</pattern>
        </encoder>
    </appender>

    <root level="INFO">
        <appender-ref ref="CONSOLE"/>
    </root>
</configuration>
```

### 로그 출력 예시

```
2026-04-22 14:20:00.123 INFO  [a1b2c3d4e5f6g7h8] c.e.u.c.UserController - Request received
2026-04-22 14:20:00.234 WARN  [a1b2c3d4e5f6g7h8] c.e.c.e.GlobalExceptionHandler - [BusinessException] GET /api/v1/users/999 - User not found
```

---

## 의존성

### build.gradle

```gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-validation'
    implementation 'org.springframework.boot:spring-boot-starter-security' // AccessDeniedException용, 미사용 시 제거
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}
```

---

## 응답 예시

### 성공 - 단일 객체

```http
GET /api/v1/users/1
HTTP/1.1 200 OK
X-Trace-Id: a1b2c3d4e5f6g7h8
```

```json
{
  "success": true,
  "code": "OK",
  "message": "Success",
  "data": {
    "id": 1,
    "email": "user@example.com",
    "name": "Jhyun"
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

### 성공 - 페이지 목록

```http
GET /api/v1/users?page=0&size=10
HTTP/1.1 200 OK
```

```json
{
  "success": true,
  "code": "OK",
  "message": "Success",
  "data": {
    "content": [
      { "id": 1, "email": "a@b.com" },
      { "id": 2, "email": "c@d.com" }
    ],
    "page": 0,
    "size": 10,
    "totalElements": 42,
    "totalPages": 5,
    "hasNext": true,
    "hasPrevious": false
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

### 성공 - 생성

```http
POST /api/v1/users
HTTP/1.1 201 Created
```

```json
{
  "success": true,
  "code": "OK",
  "message": "User created",
  "data": {
    "id": 42,
    "email": "new@example.com"
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

### 실패 - 검증 오류

```http
POST /api/v1/users
HTTP/1.1 400 Bad Request
```

```json
{
  "success": false,
  "code": "C001",
  "message": "Invalid input value",
  "error": {
    "errorCode": "C001",
    "fieldErrors": [
      {
        "field": "email",
        "rejectedValue": "abc",
        "reason": "must be a well-formed email address"
      },
      {
        "field": "password",
        "rejectedValue": "123",
        "reason": "size must be between 8 and 64"
      }
    ]
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

### 실패 - 비즈니스 예외

```http
GET /api/v1/users/999
HTTP/1.1 404 Not Found
```

```json
{
  "success": false,
  "code": "U001",
  "message": "User not found",
  "error": {
    "errorCode": "U001"
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

### 실패 - 인증 오류

```http
GET /api/v1/users/1
HTTP/1.1 401 Unauthorized
```

```json
{
  "success": false,
  "code": "A003",
  "message": "Token expired",
  "error": {
    "errorCode": "A003"
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

### 실패 - 서버 오류

```http
GET /api/v1/users/1
HTTP/1.1 500 Internal Server Error
```

```json
{
  "success": false,
  "code": "C999",
  "message": "Server error",
  "error": {
    "errorCode": "C999"
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-04-22T14:20:00"
}
```

---

## 확장 가이드

### 새 도메인 추가

1. `ErrorCode` enum에 도메인 prefix로 에러 추가 (예: `O001` Order)
2. Service에서 `throw new BusinessException(ErrorCode.XXX)` 사용
3. Controller는 `ApiResponse.ok(...)`로 성공 응답만 신경

### 새 예외 타입 추가

`GlobalExceptionHandler`에 `@ExceptionHandler` 메서드만 추가하면 된다. 기존 Controller 코드 수정 불필요.

### 버전 관리

- 클라이언트 호환성을 위해 스키마 변경 시 신중하게 처리
- 필드 추가는 안전 (Jackson은 알 수 없는 필드를 무시)
- 필드 삭제/이름 변경은 breaking change

---

*Last updated: 2026-04-24*
