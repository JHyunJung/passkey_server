# Crosscert Multi-Tenant Passkey Server

카드/금융 RP를 위한 멀티테넌트 FIDO2/WebAuthn 인증 플랫폼. PRD v1.0 (2026-05-15) 기준 M1~M5 구현 완료. 이후 Oracle 19c VPD 이식 + Admin Console SPA + Java RP SDK 추가.

## 디렉토리

| Path | 설명 |
|------|------|
| `server/` | Spring Boot 3.5.x + Java 17 백엔드 (WebAuthn 코어 + RP API + Admin REST API) |
| `admin/` | Admin Console SPA — Vite + React 18 + TypeScript + Tailwind + shadcn/ui + TanStack Query |
| `sdk/` | TypeScript npm 패키지 (`@crosscert/passkey-sdk`) — 브라우저용 SDK |
| `sdk-java/` | Java RP SDK — `passkey-rp-sdk-core` + `passkey-rp-spring-boot-starter` + `passkey-rp-sdk-bom`. RP 백엔드용 (ceremony 프록시 + JWT 검증) |
| `docs/` | Architecture, integration guide, error code catalog, deployment guide, RP Java SDK 가이드, 계정 복구 절차 |
| `admin-console-docs/` | Admin Console 원본 PRD + action plan + 배포 가이드 |
| `multi-tenant-passkey-server-prd.md` | 원본 PRD |
| `multi-tenant-passkey-server-action-plan.md` | 솔로 개발 액션 플랜 |
| `spring-boot-api-response-template.md` | API Response 표준 템플릿 |

## 빠르게 시작

### 원샷 (권장)

```bash
scripts/dev-up.sh -y          # DB 리셋 + 서버 3종 부팅 + tenant/API key 자동 발급
# … 끝나면 .env.dev에 PASSKEY_TENANT_ID/PASSKEY_API_KEY가 떨어져 있음
scripts/dev-down.sh           # 서버만 종료 (Oracle/Redis 유지)
scripts/dev-down.sh --infra   # 컨테이너까지 종료
```

스크립트가 띄우는 것:
- **Passkey 서버** `:8080` (admin REST API + RP API + swagger)
- **RP demo** `:8090` (passkey-rp-spring-boot-starter 예제)
- **Admin 콘솔** `:5173` (Vite dev) — 로그인 `dev@local.test` / `devpassword!`

로그는 `logs/*.log`. 매 실행마다 직전 로그는 `logs/archive/<timestamp>/`로 보존.

### 수동 부팅 (개별 컴포넌트만 띄우고 싶을 때)

```bash
cd server
docker compose up -d                                    # Oracle 19c-compatible + Redis
./gradlew bootRun --args='--spring.profiles.active=local'
```

`local` 프로파일은 `DevAdminBootstrap`이 PLATFORM_OPERATOR 계정(`dev@local.test` / `devpassword!`)을 자동 시드하므로 SQL 부트스트랩이 필요 없습니다. Admin 콘솔 연동 테스트 시에는 `--passkey.admin.enabled=true`도 함께 전달합니다.

다른 터미널에서 (Admin REST API로 tenant 생성 → API key 발급):
```bash
# 1) XSRF 토큰 확보 후 로그인 (CookieCsrfTokenRepository — 첫 요청 응답의 XSRF-TOKEN을 echo)
curl -s -c /tmp/cookie.txt http://localhost:8080/api/v1/admin/auth/login -o /dev/null
XSRF=$(grep XSRF-TOKEN /tmp/cookie.txt | awk '{print $NF}')
curl -s -c /tmp/cookie.txt -b /tmp/cookie.txt -X POST http://localhost:8080/api/v1/admin/auth/login \
  -H 'Content-Type: application/json' -H "X-XSRF-TOKEN: $XSRF" \
  -d '{"email":"dev@local.test","password":"devpassword!"}'

# 2) tenant 생성
curl -s -b /tmp/cookie.txt -X POST http://localhost:8080/api/v1/admin/tenants \
  -H 'Content-Type: application/json' -H "X-XSRF-TOKEN: $XSRF" \
  -d '{"name":"Test Card","slug":"test-card"}'
```

### Admin Console

```bash
cd admin
npm install
npm run dev          # http://localhost:5173 — /api/* 는 Vite proxy로 :8080 전달
```

### SDK

```bash
cd sdk               # 브라우저 TypeScript SDK
npm install && npm run build

cd sdk-java          # Java RP SDK
./gradlew build
```

## 마일스톤 진행

| Milestone | 상태 | 산출물 |
|-----------|------|--------|
| M1 Foundation | ✅ | 멀티테넌트 데이터 모델 + RLS, 예외 인프라, 트레이스 ID |
| M2 WebAuthn Core | ✅ | webauthn4j 통합, 등록/인증 ceremony, signature counter, 자격증명 lifecycle, attestation policy |
| M3 Platform Services | ✅ | JWT, RP API key (Argon2), rate limit, audit log (partitioned + hash chain), monitoring counter |
| M4-A Customer-Facing | ✅ | Spring Security, Admin REST API, JS SDK npm 패키지 |
| M4-B Admin SPA | ✅ | Vite + React 18 Admin Console (`admin/`) — tenant/WebAuthn config/API key/credential/audit/funnel + end-user 조회 |
| M5 Launch Prep | ✅ | Dockerfile, prod profile, hardening, 문서 |

> M1~M5 이후 Oracle 19c VPD 이식(v1.5), End-user 조회 뷰, cross-tenant 플랫폼 통계, RS256 JWT, Java RP SDK가 추가되었습니다. 최신 변경 내역은 [architecture.md §11 변경 이력](./docs/architecture.md) 참조.

## 문서

- [**아키텍처 + 엔티티 모델 + 서비스 흐름**](./docs/architecture.md) — 새 합류자/리뷰어 시작점
- [통합 가이드](./docs/integration-guide.md) — RP 개발자용 (브라우저 JS SDK)
- [RP Java SDK 가이드](./docs/rp-java-sdk.md) — RP 백엔드용 Spring Boot starter
- [에러 코드 카탈로그](./docs/error-codes.md)
- [배포 가이드](./docs/deployment.md)
- [계정 복구 운영 절차](./docs/account-recovery.md)
- [SDK README](./sdk/README.md)
- [DB 마이그레이션 컨벤션](./server/docs/migrations.md)

## 핵심 invariants (M1+ 유지)

> v1.5에서 PostgreSQL RLS → Oracle 19c Virtual Private Database(VPD)로 이식. 격리 메커니즘이 바뀌었습니다.

1. 모든 DB 접근은 `@Transactional` 안에서만
2. 모든 테넌트 스코프 테이블은 `DBMS_RLS.ADD_POLICY`로 VPD 정책 부착 (`R__vpd_policies.sql`)
3. `APP_RUNTIME`은 `EXEMPT ACCESS POLICY` 미부여 (VPD 적용). `APP_ADMIN`은 `EXEMPT ACCESS POLICY` 부여 (Platform Operator cross-tenant 조회 전용)
4. 테넌트 컨텍스트 미설정 → 정책 함수가 `'1 = 0'` predicate 반환 → 모든 SELECT 0 rows (fail-closed)
5. `TenantResolver`는 인터페이스 — local 헤더 / RP API key / admin session 교체 가능
6. Hibernate `getConnection(tenantId)`에서 `passkey_ctx_pkg.set_tenant` 단일 지점, connection 반납 시 `clear_tenant`
7. `ApiResponse` envelope 모든 응답에 적용
8. VPD 정책은 `R__vpd_policies.sql`로 desired-state 관리 (`RlsPolicyCatalogTest`가 catalog 검증)
9. URL prefix `/api/v1/rp/`, `/api/v1/admin/`, `/_diag/` 세 그룹만 허용 (ArchUnit 강제)
10. `ErrorCode`는 단일 enum + 도메인 prefix(C/A/T/P/R/D/M) + 3자리 번호

## 라이선스

Internal.
