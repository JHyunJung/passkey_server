# RP Java SDK

이 문서는 Crosscert Passkey 플랫폼을 **Java/Spring Boot 기반 RP(Relying Party) 백엔드**에 통합하기 위한 `passkey-rp-sdk` 사용 명세입니다. 브라우저용 `@crosscert/passkey-sdk`(JS SDK)와는 별개로, RP 백엔드가 패스키 서버와 통신할 때 사용합니다.

> 브라우저 통합은 [integration-guide.md](integration-guide.md)를, 에러 코드 전체 목록은 [error-codes.md](error-codes.md)를 참조하세요.

## 목차

1. [구성](#1-구성)
2. [설치](#2-설치)
3. [설정 (application.yml)](#3-설정-applicationyml)
4. [멀티테넌트](#4-멀티테넌트)
5. [Client → RP 서버 API 명세](#5-client--rp-서버-api-명세)
6. [응답 Envelope](#6-응답-envelope)
7. [에러 코드](#7-에러-코드)
8. [JWT 검증](#8-jwt-검증)
9. [관측성](#9-관측성)
10. [서버 측 선결 조건](#10-서버-측-선결-조건)

---

## 1. 구성

SDK는 3개 Gradle 모듈로 구성됩니다.

| 모듈 | 내용 |
|------|------|
| `passkey-rp-sdk-core` | 순수 Java 17. Spring 의존성 없음 (ArchUnit으로 강제). HTTP 클라이언트, DTO, 예외 계층, JWT 검증기 |
| `passkey-rp-spring-boot-starter` | Spring Boot 3.5 auto-configuration. 의존성만 추가하면 5개 엔드포인트·필터·예외 핸들러가 자동 마운트 |
| `passkey-rp-sdk-bom` | 두 모듈의 버전을 정렬하는 BOM POM |

### core 모듈 패키지

| 패키지 | 핵심 타입 |
|--------|-----------|
| `client` | `PasskeyClient`(8개 메서드 facade), `DefaultPasskeyClient`(단일 tenant), `MultiTenantPasskeyClient`(tenant별 client 캐싱), `JdkPasskeyHttpClient`(`java.net.http` 기반), `RetryPolicy` |
| `dto` | 서버 wire 형식과 1:1 대응하는 record 12개 + `ApiResponse<T>` envelope |
| `error` | `ErrorCode` enum + 11개 typed exception + `ErrorTranslator` |
| `jwt` | `NimbusJwtVerifier`(RS256 + JWKS 로컬 검증), `RefreshTokenManager`, `VerifiedToken` |
| `tenant` | `ApiKeyResolver` SPI + `FixedApiKeyResolver` |

### starter 모듈 컴포넌트

| 컴포넌트 | 역할 |
|----------|------|
| `PasskeyAutoConfiguration` | 모든 빈 자동 생성, fail-fast 검증 |
| `PasskeyProperties` | `passkey.rp.**` 설정 바인딩 |
| `PasskeyJwtAuthenticationFilter` | `Authorization: Bearer` → `SecurityContext`, `tid` claim 교차검증 |
| `PasskeyCeremonyController` | `/passkey/**` 5개 엔드포인트 즉시 마운트 |
| `PasskeyExceptionHandler` | SDK 예외 → `ApiResponse` envelope 매핑 |
| `PasskeyMdcFilter` | `X-Trace-Id` ↔ MDC 전파 |
| `PasskeyMeterBinder` | 서버와 정렬된 Micrometer 메트릭 |

---

## 2. 설치

> 현재 Maven Central 미배포. 사내 nexus publish 또는 로컬 설치로 사용합니다.

```bash
# SDK 빌드 후 로컬 Maven 저장소(~/.m2)에 설치
cd sdk-java
./gradlew publishToMavenLocal
```

RP 프로젝트의 `build.gradle.kts`:

```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("com.crosscert.passkey:passkey-rp-spring-boot-starter:0.1.0-SNAPSHOT")
}
```

starter를 추가하면 `passkey-rp-sdk-core`는 전이 의존성으로 함께 포함됩니다.

---

## 3. 설정 (application.yml)

### 단일 tenant — 최소 설정

```yaml
passkey:
  rp:
    base-url: https://passkey.example.com
    api-key: ${PASSKEY_API_KEY}        # 어드민 콘솔에서 발급
    tenant-id: 0123abcd-...            # JWT tid claim 검증용 (필수)
```

이 세 줄만으로 자동 활성화되는 것:

- `/passkey/register/begin`·`finish`, `/passkey/authenticate/begin`·`finish`, `/passkey/refresh`
- `Authorization: Bearer` JWT 검증 필터 (RS256 + JWKS 로컬 검증)
- `ApiResponse` 형식 예외 핸들러, traceId 필터, 메트릭

### 전체 설정 키

```yaml
passkey:
  rp:
    base-url: ${PASSKEY_BASE_URL:https://passkey.example.com}
    api-key: ${PASSKEY_API_KEY:}        # single-tenant 필수
    tenant-id:                          # single-tenant 필수 (tid 검증)
    issuer: passkey-platform            # JWT iss claim
    jwks-uri:                           # 미설정 시 base-url/.well-known/jwks.json
    jwks-cache-ttl: 1h
    http:
      connect-timeout: 2s
      read-timeout: 10s
      max-retries: 3
      retry-base-backoff: 200ms
    auth:
      mode: jwt                         # jwt | session | off
      jwt:
        clock-skew: 60s
        header-name: Authorization
      session:
        attribute-name: PASSKEY_USER
        invalidate-on-reuse: true
    ceremony:
      controller-enabled: true          # drop-in 컨트롤러 on/off
      path-prefix: /passkey
    multi-tenant:
      enabled: false
      resolver-bean: passkeyApiKeyResolver
    observability:
      metrics-enabled: true
      mdc-trace-header: X-Trace-Id
```

| 키 | 기본값 | 설명 |
|----|--------|------|
| `base-url` | — | 패스키 서버 base URL (필수) |
| `api-key` | — | single-tenant 모드에서 필수 |
| `tenant-id` | — | single-tenant 모드에서 필수. JWT `tid` 검증 |
| `auth.mode` | `jwt` | `jwt`(stateless) / `session`(서버 세션) / `off` |
| `ceremony.controller-enabled` | `true` | `false`면 RP가 직접 컨트롤러 작성 |
| `multi-tenant.enabled` | `false` | `true`면 `ApiKeyResolver` 빈 직접 등록 필요 |

---

## 4. 멀티테넌트

RP가 자기 고객에게 재판매하는 SaaS 형태라면 멀티테넌트 모드를 사용합니다.

```yaml
passkey:
  rp:
    base-url: https://passkey.example.com
    multi-tenant:
      enabled: true
      resolver-bean: myTenantResolver
```

RP는 `ApiKeyResolver` 빈을 직접 등록합니다. 요청 컨텍스트(`HttpServletRequest`)로 tenant를 판별하고 해당 API key를 반환합니다.

```java
@Bean("myTenantResolver")
ApiKeyResolver myTenantResolver() {
  return ctx -> {
    HttpServletRequest req = (HttpServletRequest) ctx;
    String subdomain = extractSubdomain(req.getServerName());
    TenantConfig cfg = tenantConfigStore.bySubdomain(subdomain);
    return new ApiKeyResolver.TenantBinding(cfg.tenantId(), cfg.apiKey());
  };
}
```

- `MultiTenantPasskeyClient`가 tenant UUID별로 client를 `ConcurrentHashMap`에 캐싱
- `multi-tenant.enabled=true`인데 resolver 빈이 없으면 startup 시 fail-fast
- JWT 필터가 verified `tid` claim과 resolver가 결정한 tenant 일치 여부 검증 (cross-tenant 토큰 재사용 방어)

---

## 5. Client → RP 서버 API 명세

`PasskeyCeremonyController`가 마운트하는 엔드포인트입니다. Client(앱/웹)는 RP 백엔드의 이 경로로 호출하며, RP 백엔드가 내부에서 `X-API-Key`를 붙여 패스키 서버로 forward합니다. **Client는 API key를 다루지 않습니다.**

| 항목 | 내용 |
|------|------|
| Base path | `/passkey` (`ceremony.path-prefix`로 변경 가능) |
| Content-Type | `application/json` |
| 인증 | ceremony 엔드포인트는 인증 불필요. 보호 API는 `Authorization: Bearer <accessToken>` |
| 응답 형식 | 성공·실패 모두 [`ApiResponse` envelope](#6-응답-envelope) |

### 5.1 등록 시작 — `POST /passkey/register/begin`

**Request**

```json
{ "externalUserId": "user-12345", "displayName": "홍길동" }
```

**Response 200** — `data`: `RegistrationOptionsResponse`

```json
{
  "ceremonyId": "uuid",
  "challenge": "base64url",
  "rp":   { "id": "example.com", "name": "Example" },
  "user": { "id": "base64url(16B)", "name": "user-12345", "displayName": "홍길동" },
  "pubKeyCredParams": [ { "type": "public-key", "alg": -7 } ],
  "timeout": 60000,
  "attestation": "none",
  "authenticatorSelection": {
    "userVerification": "preferred",
    "residentKey": "preferred",
    "requireResidentKey": false
  },
  "excludeCredentials": [
    { "type": "public-key", "id": "base64url", "transports": "internal,hybrid" }
  ],
  "extensions": {}
}
```

> `challenge`·`user.id`·`excludeCredentials[].id`는 base64url → ArrayBuffer 디코드 후 `navigator.credentials.create()`에 전달합니다.
> `excludeCredentials`·`extensions`는 비어 있으면 응답에서 생략됩니다.

### 5.2 등록 완료 — `POST /passkey/register/finish`

**Request**

```json
{
  "ceremonyId": "uuid",
  "credentialId": "base64url",
  "clientDataJsonB64u": "base64url",
  "attestationObjectB64u": "base64url",
  "transports": "internal,hybrid",
  "nickname": "내 아이폰"
}
```

| 필드 | 필수 | 설명 |
|------|------|------|
| `ceremonyId` | ✓ | begin 응답에서 받은 값 |
| `transports` | — | 쉼표 구분 문자열 |
| `nickname` | — | credential 표시 이름 |

**Response 201 Created** — `data`: `RegistrationResult`

```json
{ "credentialDbId": "uuid", "credentialId": "base64url", "aaguid": "uuid" }
```

> 패스키 서버는 `register/verify`에 대해 HTTP 201을 반환합니다. SDK는 모든 2xx를 성공으로 처리하므로 RP·Client 코드는 별도 분기가 필요 없습니다.

### 5.3 인증 시작 — `POST /passkey/authenticate/begin`

**Request**

```json
{ "externalUserId": "user-12345" }
```

> `externalUserId`를 생략하면 discoverable credential(usernameless) 흐름입니다.

**Response 200** — `data`: `AuthenticationOptionsResponse`

```json
{
  "ceremonyId": "uuid",
  "challenge": "base64url",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [
    { "type": "public-key", "id": "base64url", "transports": "internal" }
  ],
  "userVerification": "preferred"
}
```

### 5.4 인증 완료 — `POST /passkey/authenticate/finish`

**Request**

```json
{
  "ceremonyId": "uuid",
  "credentialId": "base64url",
  "clientDataJsonB64u": "base64url",
  "authenticatorDataB64u": "base64url",
  "signatureB64u": "base64url",
  "userHandleB64u": "base64url"
}
```

| 필드 | 필수 | 설명 |
|------|------|------|
| `userHandleB64u` | — | discoverable 흐름에서 채워짐 |

**Response 200** — `data`: `AuthenticationResult`

```json
{
  "credentialDbId": "uuid",
  "tenantUserId": "uuid",
  "credentialId": "base64url",
  "signatureCounter": 42,
  "accessToken": "<JWT RS256>",
  "refreshToken": "<JWT>",
  "accessExpiresIn": 900
}
```

> `accessToken`(기본 15분)·`refreshToken`(기본 30일)이 발급됩니다.
> `auth.mode=session`이면 RP 세션에 사용자 식별자가 자동 주입됩니다.

### 5.5 토큰 갱신 — `POST /passkey/refresh`

**Request**

```json
{ "refreshToken": "<JWT>" }
```

**Response 200** — `data`: `RefreshResult`

```json
{ "accessToken": "<new JWT>", "refreshToken": "<new JWT>", "accessExpiresIn": 900 }
```

> refresh token은 호출 시마다 회전(rotation)됩니다. 이미 사용된 refresh token을 재제출하면 서버가 전체 rotation family를 폐기(family burn)하고 `401 + Clear-Site-Data` 를 반환합니다 — 강제 로그아웃 신호입니다.

> 참고: SDK `PasskeyClient`에는 `listCredentials` / `renameCredential` / `deleteCredential`도 있습니다. 이들은 RP 백엔드 코드에서 직접 호출하는 메서드로, `PasskeyCeremonyController`가 기본 노출하는 5개 ceremony 엔드포인트와는 별개입니다. 패스키 서버의 `DELETE /api/v1/rp/passkeys/{id}`는 HTTP 204(빈 본문)를 반환하며, SDK가 이를 정상 성공으로 처리합니다.

### 5.6 전형적 호출 흐름

```
[등록]   register/begin  →  navigator.credentials.create()  →  register/finish
[로그인] authenticate/begin → navigator.credentials.get()  →  authenticate/finish  →  accessToken 획득
[유지]   accessToken 만료 시  →  refresh
```

---

## 6. 응답 Envelope

모든 응답은 패스키 서버의 `ApiResponse<T>` 템플릿(`spring-boot-api-response-template.md`)과 동일한 스키마입니다. 성공·실패가 같은 구조이므로 Client는 에러 파싱을 따로 분기할 필요가 없습니다.

```jsonc
{
  "success": true | false,
  "code": "OK" | "P002" | "A012" | ...,   // 성공="OK", 실패=도메인 코드
  "message": "Success" | "에러 메시지",
  "data": { ... } | null,                  // 성공 시 payload, 실패 시 생략
  "error": {                                // 실패 시에만 존재
    "errorCode": "P002",
    "fieldErrors": [
      { "field": "...", "rejectedValue": "...", "reason": "..." }
    ]
  },
  "traceId": "...",
  "timestamp": "2026-05-20T10:00:00"
}
```

- `@JsonInclude(NON_NULL)` — `data`는 에러 시, `error`는 성공 시 생략
- 모든 응답 헤더에 `X-Trace-Id` 포함. 요청에 `X-Trace-Id`를 보내면 그대로 전파

---

## 7. 에러 코드

`PasskeyExceptionHandler`가 SDK 예외를 다음 HTTP 응답으로 매핑합니다. 코드 전체 의미는 [error-codes.md](error-codes.md) 참조.

| HTTP | code | 의미 | 특수 헤더 | SDK 예외 |
|------|------|------|-----------|----------|
| 400 | C001 | 입력 검증 실패 | | `PasskeyApiException` |
| 400 | P002 | challenge 만료/없음 | | `ChallengeExpiredException` |
| 400 | P003/P004 | attestation/assertion 검증 실패 | | `PasskeyCeremonyException` |
| 401 | A003 | access token 만료 | `WWW-Authenticate: Bearer error=token_expired` | `PasskeyAuthenticationException` |
| 401 | A004 | invalid token | `WWW-Authenticate: Bearer error=invalid_token` | `PasskeyAuthenticationException` |
| 401 | A005 | invalid API key | | `PasskeyAuthenticationException` |
| 401 | A011 | refresh token revoked | | `RefreshTokenRevokedException` |
| 401 | A012 | refresh token 재사용 감지 | `Clear-Site-Data: "cookies"` | `RefreshReuseDetectedException` |
| 401 | P005 | signature counter regression | | `CounterRegressionException` |
| 401 | P007 | credential revoked | | `CredentialRevokedException` |
| 403 | P008 | AAGUID 미허용 | | `AaguidRejectedException` |
| 429 | R001 | rate limit 초과 | `Retry-After` | `PasskeyRateLimitException` |
| 503 | — | 패스키 서버 통신 실패 | | `PasskeyTransportException` |

RP 코드에서 더 높은 우선순위의 `@RestControllerAdvice`를 선언하면 개별 매핑을 재정의할 수 있습니다.

---

## 8. JWT 검증

`auth.mode=jwt`(기본)일 때 `PasskeyJwtAuthenticationFilter`가 모든 요청의 `Authorization: Bearer` 헤더를 검사합니다.

- **알고리즘**: RS256. 패스키 서버의 `/.well-known/jwks.json`에서 공개키를 가져와 **로컬 검증** — 매 요청마다 서버를 호출하지 않습니다.
- **캐시**: Nimbus 내장 refresh-ahead 캐시. `jwks-cache-ttl`(기본 1시간) 동안 JWKS를 재사용.
- **검증 항목**: 서명, `iss`(issuer), `typ=access`(refresh-as-access 혼동 방어), `iat`/`exp`(clock skew 허용), `tid`(테넌트 일치).
- **검증 성공 시**: `SecurityContext`에 `PasskeyPrincipal`(tenantId, tenantUserId, externalUserId, expiresAt) 주입.

`auth.mode=session`이면 인증 성공 후 `PasskeyPrincipal`을 `HttpSession`(`session.attribute-name`)에 저장합니다.

```java
// 컨트롤러에서 인증된 사용자 접근
@GetMapping("/me")
public String me(@AuthenticationPrincipal PasskeyPrincipal principal) {
  return principal.externalUserId();
}
```

---

## 9. 관측성

`observability.metrics-enabled=true`(기본)이고 classpath에 Micrometer가 있으면 다음 카운터가 등록됩니다. 패스키 서버와 **동일한 메트릭 이름**이라 대시보드가 정렬됩니다.

| 메트릭 | 의미 |
|--------|------|
| `passkey.security.tid_mismatch` | JWT `tid`와 resolver tenant 불일치 — 토큰 재사용 의심 신호 |
| `passkey.security.jwt_verify_failed` | JWT 검증 실패 |
| `passkey.security.refresh_reuse_detected` | refresh token 재사용 감지 |

`PasskeyMdcFilter`가 모든 요청에 `traceId`를 MDC에 넣고 응답 헤더(`X-Trace-Id`)로 노출하므로, 로그와 응답을 traceId로 매칭할 수 있습니다.

---

## 10. 서버 측 선결 조건

JWT 로컬 검증(RS256 + JWKS)을 사용하려면 패스키 **서버**가 RS256 모드여야 합니다.

```bash
# 패스키 서버 env
PASSKEY_JWT_ALGORITHM=RS256
PASSKEY_JWT_RSA_PRIVATE_PEM=...   # PKCS#8 PEM
PASSKEY_JWT_RSA_PUBLIC_PEM=...    # SPKI PEM
PASSKEY_JWT_KID=2026-05-A
```

서버가 RS256으로 부팅되면 `GET /.well-known/jwks.json`이 공개키를 노출하고, SDK가 이를 캐싱하여 검증합니다. 키 회전 시에는 `PASSKEY_JWT_*_PREVIOUS` + `PASSKEY_JWT_KID_PREVIOUS`를 설정해 무중단 전환합니다. 자세한 절차는 [deployment.md](deployment.md)를 참조하세요.

> 서버가 HS256 모드면 JWKS는 빈 키셋을 반환하며, SDK의 JWT 로컬 검증은 사용할 수 없습니다.

---

## 변경 이력

| 날짜 | 내용 |
|------|------|
| 2026-05-20 | 최초 작성. `passkey-rp-sdk` 0.1.0 기준 |
