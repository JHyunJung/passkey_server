# Passkey 플랫폼 기능 명세서 (Capability Spec)

멀티테넌트 FIDO2/WebAuthn 패스키 인증 플랫폼을 **처음 설계한다는 관점**에서, 4개 컴포넌트가 각각 어떤 핵심 기능을 갖춰야 하는지 정리한 문서다.

- **목적**: 구현 세부와 무관하게 "이 컴포넌트는 무엇을 할 수 있어야 하는가"의 체크리스트.
- **범위**: MVP 경계 — 각 컴포넌트가 제 역할을 하기 위해 **반드시 있어야 하는 기능**에 한정한다. 셀프 회원가입, 알림(이메일/SMS), MAU 과금/미터링, i18n 등 "있으면 좋은" 기능은 비목표로 명시한다.
- **대상 독자**: 신규 합류 개발자, 통합 담당 RP 개발자, 제품/보안 리뷰어.
- 실제 구현 현황·엔드포인트 경로는 [architecture.md](./architecture.md)·[integration-guide.md](./integration-guide.md)·[rp-java-sdk.md](./rp-java-sdk.md) 참조.

---

## 0. 시스템 구성과 컴포넌트 책임

```
   ┌─────────────────┐     X-API-Key      ┌──────────────────────┐
   │ 브라우저 JS SDK │ ──(RP 백엔드 경유)──→ │                      │
   └─────────────────┘                    │                      │
   ┌─────────────────┐  ceremony 프록시    │   Passkey 서버        │
   │ RP 백엔드        │ ──(Java RP SDK)──→  │   (인증 권위 + 멀티   │
   │ (+ Java RP SDK) │ ←──JWKS 공개키──     │    테넌트 데이터)      │
   └─────────────────┘                    │                      │
   ┌─────────────────┐    세션 쿠키        │                      │
   │ Admin Console   │ ──────────────────→ │                      │
   └─────────────────┘                    └──────────────────────┘
```

| 컴포넌트 | 한 줄 책임 | 신뢰 경계 |
|----------|-----------|-----------|
| **Passkey 서버** | 패스키 ceremony·자격증명·토큰의 단일 권위. 멀티테넌트 데이터 소유 | 플랫폼 운영자 통제 |
| **RP 서버 (+ Java RP SDK)** | RP의 백엔드. API key 보유, end-user 신원과 패스키를 연결 | RP(고객사) 통제 |
| **브라우저 JS SDK** | RP 프론트엔드에서 WebAuthn API를 호출, ceremony 데이터를 RP 백엔드와 중계 | 신뢰 불가(공개 코드) |
| **Admin Console** | 운영자·RP 관리자가 테넌트·정책·자격증명을 관리하는 웹 UI | 운영자/RP 관리자 |

핵심 원칙: **API key·시크릿은 절대 브라우저에 두지 않는다.** 브라우저 SDK는 RP 백엔드를 통해서만 서버와 통신하고, RP 백엔드만 API key를 보유한다.

---

## 1. Passkey 서버 — 인증 권위(Authentication Authority)

플랫폼의 심장. 모든 ceremony 검증, 자격증명 저장, 토큰 발급, 테넌트 데이터를 소유한다.

### 1.1 RP-facing 기능 (API key 인증)

RP 백엔드가 호출하는 기능. 모든 요청은 테넌트별 API key로 인증된다.

| 기능 | 설명 |
|------|------|
| **등록 옵션 발급** | end-user에 대한 WebAuthn 등록 ceremony를 시작 — challenge·RP 정보·이미 등록된 자격증명 제외 목록(`excludeCredentials`)을 담은 옵션 생성 |
| **등록 검증** | 브라우저가 만든 attestation을 검증 — challenge 일치, origin/rpId 일치, attestation 신뢰성(정책에 따라), 자격증명 영속화 |
| **인증 옵션 발급** | 로그인 ceremony 시작 — challenge + 해당 user의 허용 자격증명 목록(`allowCredentials`) |
| **인증 검증** | assertion 검증 — 서명·challenge·signature counter 검증 후 액세스/리프레시 토큰 발급 |
| **토큰 갱신** | 리프레시 토큰을 회전(rotate)하여 새 토큰 쌍 발급. reuse 감지 시 토큰 패밀리 전체 무효화 |
| **자격증명 목록 조회** | 특정 end-user가 등록한 패스키 목록 (nickname·기기 정보·마지막 사용 시각) |
| **자격증명 이름 변경 / 폐기** | end-user 본인의 패스키 관리. **소유권 검증 필수** — 다른 user의 자격증명 ID를 알아도 조작 불가(IDOR 방어) |

### 1.2 Admin-facing 기능 (세션 인증)

운영자·RP 관리자가 Admin Console을 통해 호출하는 기능.

| 기능 카테고리 | 핵심 기능 |
|---------------|-----------|
| **테넌트 관리** | 테넌트 생성·조회·목록·상태 변경(활성/정지). 테넌트는 격리 단위 |
| **WebAuthn 설정** | 테넌트별 rpId·origins·user verification 정책·attestation conveyance·resident key·credProtect 설정. **이 설정이 없으면 ceremony 불가** |
| **Attestation 정책** | AAGUID(authenticator 모델 식별자) allowlist/blocklist, MDS strict 모드 토글 |
| **API key 관리** | 테넌트별 RP API key 발급(평문은 발급 시 1회만 노출)·목록·폐기 |
| **자격증명 관리** | 테넌트 내 전체 패스키 목록·검색·통계, 운영자 강제 폐기, cross-tenant 재할당 |
| **End-user 조회** | 테넌트의 end-user 목록·검색, 개별 user의 패스키와 최근 활동 조회(읽기 전용) |
| **Audit 로그 조회** | 이벤트 타입 필터·페이징 조회, **해시 체인 무결성 검증 UI** (위변조 탐지) |
| **퍼널 지표** | 등록/인증 ceremony의 성공률·전환율 시계열 |
| **플랫폼 통계** | 운영자 전용 — 전체 테넌트 합산 지표(자격증명 수, 유효 API key, ceremony 수) |
| **운영자 계정 관리** | 운영자 전용 — 플랫폼 운영자·RP 관리자 계정 발급·관리 |
| **시스템 운영** | 운영자 전용 — MDS 메타데이터 강제 갱신, rate-limit 현황 조회 |

### 1.3 횡단 플랫폼 기능 (모든 요청에 적용)

| 기능 | 설명 | 왜 필수인가 |
|------|------|------------|
| **멀티테넌트 격리** | 모든 테넌트 스코프 데이터는 요청의 테넌트 컨텍스트로 자동 필터링. 컨텍스트 미설정 시 0건 반환(fail-closed) | 한 테넌트가 다른 테넌트 데이터를 절대 볼 수 없어야 함 |
| **API key 인증** | RP API key를 해시로만 저장(평문 미보관), 검증 결과 캐싱, 폐기 시 모든 인스턴스에 즉시 전파 | RP 신원 확인의 단일 관문 |
| **JWT 토큰 발급/검증** | 인증 성공 시 액세스(단명)·리프레시(장명) 토큰 발급. 대칭(HS256) 또는 비대칭(RS256) 서명. RS256은 공개키를 JWKS로 노출해 RP가 시크릿 공유 없이 검증 | RP가 자체 세션을 만들 수 있는 신뢰 근거 |
| **리프레시 토큰 회전** | 리프레시 토큰은 1회용 — 사용 시 회전되고, 재사용 감지 시 토큰 패밀리 전체 무효화 | 토큰 탈취 공격 차단 |
| **Rate limiting** | ceremony·로그인 등 민감 엔드포인트에 테넌트별·IP별 호출 제한 | brute-force·자원 고갈 방어 |
| **Audit 로그** | 모든 보안 의미 이벤트를 추가 전용(append-only) 기록, 테넌트별 해시 체인으로 위변조 탐지 가능 | 컴플라이언스·포렌식 |
| **FIDO MDS 통합** | FIDO Alliance 메타데이터를 주기적으로 가져와 attestation 정책 강제에 활용 | authenticator 신뢰성 검증 |
| **세션 관리** | Admin Console용 서버 세션, 비활동 타임아웃, CSRF 보호 | 운영자 콘솔 보안 |

**비목표 (서버 MVP 제외)**: 셀프 RP 온보딩, 사용량 미터링/과금, 알림 발송, 웹훅, end-user 셀프 가입 API.

---

## 2. RP 서버 (+ Java RP SDK) — RP 백엔드 통합 계층

RP(고객사)의 백엔드. end-user의 **신원**(자체 회원 DB)과 Passkey 플랫폼의 **자격증명**을 연결한다. Java RP SDK를 쓰면 이 통합을 거의 무코드로 구현할 수 있다.

### 2.1 RP 서버가 반드시 해야 하는 일

| 기능 | 설명 |
|------|------|
| **API key 보관** | Passkey 서버 API key를 시크릿 매니저에 안전하게 보관. 절대 프론트엔드로 내려보내지 않음 |
| **end-user 신원 매핑** | RP 자체 사용자 ID(`externalUserId`)와 Passkey 플랫폼 자격증명을 연결 |
| **ceremony 중계** | 브라우저 ↔ Passkey 서버 사이에서 등록/인증 ceremony 옵션·결과를 중계 (API key는 이 계층에서만 부착) |
| **토큰 검증** | 인증 성공 후 받은 액세스 토큰을 검증해 RP 자체 세션으로 전환 |
| **자격증명 관리 위임** | end-user의 "내 패스키 보기/이름변경/삭제" 요청을 서버로 위임 |

### 2.2 Java RP SDK가 자동 제공하는 것

| 기능 | 설명 |
|------|------|
| **ceremony 프록시 엔드포인트** | starter 의존성만 추가하면 등록/인증 ceremony용 HTTP 엔드포인트가 RP 백엔드에 자동 생성됨 (경로 prefix 설정 가능) |
| **JWT 인증 필터** | `Authorization: Bearer` 토큰을 자동 검증하고 인증 주체를 주입하는 Spring Security 필터. **RS256 + JWKS 전용** — 서버 공개키로 시크릿 공유 없이 검증 |
| **transport·재시도·에러 매핑** | Passkey 서버 호출의 HTTP 통신, 재시도 정책, 에러 → 타입 예외 매핑 |
| **단일/멀티 테넌트 클라이언트** | API key가 고정인 단일 테넌트, 요청별로 API key를 동적 해석하는 멀티 테넌트 두 모드 |
| **응답 표준화 + 관찰성** | 응답을 공통 envelope로 통일, Micrometer 지표·트레이스 ID 전파 |

### 2.3 통합 패턴

- RP 백엔드는 starter를 적용하고 **API key·테넌트 ID·서버 base-URL만 설정**하면 ceremony가 동작한다.
- end-user 신원 저장(회원 DB)은 RP의 책임 — SDK는 신원을 소유하지 않는다.
- 참조 구현(`passkey-rp-demo`)이 in-memory user store 기반 최소 통합 예시를 보여준다.

**비목표 (RP SDK MVP 제외)**: end-user 회원 DB 자체, 다른 언어(Node/Python/Go) SDK, 비-Spring 프레임워크 통합.

---

## 3. 브라우저 JS SDK — WebAuthn 호출 래퍼

RP 프론트엔드에서 동작. 브라우저의 WebAuthn API(`navigator.credentials`)를 감싸고, ceremony 데이터를 RP 백엔드와 주고받는다.

### 3.1 핵심 기능

| 기능 | 설명 |
|------|------|
| **패스키 등록** | 등록 ceremony 전체 수행 — RP 백엔드에서 옵션 받기 → `navigator.credentials.create()` 호출 → 결과를 RP 백엔드로 전송 |
| **패스키 인증** | 인증 ceremony 전체 수행 — 옵션 받기 → `navigator.credentials.get()` 호출 → 결과 전송 → 토큰 수령 |
| **자격증명 목록 조회** | 로그인한 end-user의 패스키 목록 표시 |
| **자격증명 이름변경 / 폐기** | end-user 셀프 서비스 패스키 관리 |
| **인코딩 유틸리티** | WebAuthn 바이너리 데이터(ArrayBuffer ↔ Base64URL) 변환 |
| **에러 처리** | WebAuthn·네트워크·서버 에러를 일관된 형태로 노출 (사용자 취소, 미지원 기기 등 구분) |

### 3.2 설계 제약

- **시크릿을 다루지 않는다** — API key는 RP 백엔드에만 있고, SDK는 RP 백엔드의 ceremony 엔드포인트만 호출한다.
- **프레임워크 비의존** — 특정 UI 프레임워크에 묶이지 않고 어떤 프론트엔드에서도 동작.
- WebAuthn 미지원 환경을 감지하고 graceful하게 알릴 수 있어야 한다.

**비목표 (JS SDK MVP 제외)**: UI 컴포넌트 제공, 자체 상태 관리, 토큰 저장(저장 위치는 RP가 결정).

---

## 4. Admin Console — 운영 관리 UI

운영자와 RP 관리자가 테넌트·정책·자격증명을 관리하는 웹 애플리케이션.

### 4.1 핵심 기능

| 기능 카테고리 | 핵심 기능 |
|---------------|-----------|
| **인증·인가** | 이메일/비밀번호 로그인, 역할 기반 라우팅 — 플랫폼 운영자는 전체 테넌트, RP 관리자는 자기 테넌트만 |
| **테넌트 관리** | 테넌트 목록·생성·상세 진입 (운영자 전용 목록) |
| **테넌트 대시보드** | 선택 테넌트의 핵심 지표 한눈에 보기(자격증명·API key·최근 ceremony) |
| **WebAuthn 설정 편집** | rpId·origins·UV 정책·attestation 등 ceremony 동작 파라미터 편집 |
| **Attestation 정책 편집** | AAGUID allowlist/blocklist 칩 입력, MDS strict 토글 |
| **API key 관리** | 발급(평문 1회 노출 모달 + 저장 확인 강제)·목록·폐기 |
| **End-user 조회** | end-user 목록·검색, 개별 user의 패스키·활동 드릴다운(읽기 전용) |
| **자격증명 관리** | 패스키 목록·검색·분포 통계, 운영자 강제 폐기·강제 로그아웃·재할당 |
| **Audit 로그 뷰어** | 이벤트 필터·페이징, payload 상세 모달, **해시 체인 무결성 검증 패널** |
| **퍼널 분석** | 등록/인증 전환율 카드 |
| **운영자 계정 관리** | 운영자 전용 — 플랫폼 admin 계정 관리 |
| **시스템 운영** | 운영자 전용 — MDS 갱신, rate-limit 모니터링 |

### 4.2 설계 제약

- **읽기/쓰기 권한 분리** — RP 관리자는 자기 테넌트 범위로만 제한, cross-tenant 기능(플랫폼 통계·재할당·운영자 관리)은 운영자 전용.
- **민감 값 1회 노출** — API key 평문은 발급 직후 1회만 보여주고, 사용자가 저장을 확인해야 닫힘.
- 별도 도메인 호스팅을 전제로 CORS·쿠키(SameSite/Secure) 정책을 서버와 합의해야 한다.

**비목표 (Admin Console MVP 제외)**: 운영자 셀프 가입, 비밀번호 셀프 재설정, 다국어, 커스텀 대시보드 위젯, 알림 센터.

---

## 5. 컴포넌트 간 의존 관계

| 호출자 | 피호출자 | 인증 수단 | 용도 |
|--------|---------|-----------|------|
| 브라우저 JS SDK | RP 백엔드 | (RP 자체 정책) | ceremony 옵션·결과 중계 |
| RP 백엔드 (+ Java SDK) | Passkey 서버 RP API | X-API-Key | ceremony 검증, 자격증명·토큰 |
| RP 백엔드 (+ Java SDK) | Passkey 서버 JWKS | 없음(공개) | RS256 액세스 토큰 검증 |
| Admin Console | Passkey 서버 Admin API | 세션 쿠키 + CSRF | 테넌트·정책·자격증명 관리 |

**불변식**: 브라우저는 절대 Passkey 서버를 직접 호출하지 않는다(API key 노출 방지). 모든 RP 트래픽은 RP 백엔드를 경유한다.

---

## 6. "처음 만든다면" 우선순위 — MVP 빌드 순서

1. **Passkey 서버 코어** — 멀티테넌트 격리 + 테넌트/WebAuthn 설정 + 등록·인증 ceremony. 이게 없으면 나머지가 의미 없다.
2. **API key 인증 + RP API** — RP가 서버를 호출할 수 있는 관문.
3. **브라우저 JS SDK** — end-user가 실제로 패스키를 만들고 쓰는 경로.
4. **JWT 발급/검증 + Java RP SDK** — RP 백엔드가 인증 결과를 자체 세션으로 전환.
5. **Admin Console** — 테넌트·API key·정책을 UI로 관리 (그 전까지는 API 직접 호출로 대체 가능).
6. **Audit 로그 + rate limiting + MDS** — 운영·컴플라이언스·보안 강화.

각 단계는 다음 단계의 전제 조건이다 — 역순으로 만들면 검증할 수단이 없다.
