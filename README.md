# Crosscert Multi-Tenant Passkey Server

카드/금융 RP를 위한 멀티테넌트 FIDO2/WebAuthn 인증 플랫폼. PRD v1.0 (2026-05-15) 기준 M1~M5 구현 완료.

## 디렉토리

| Path | 설명 |
|------|------|
| `server/` | Spring Boot 3.5.x + Java 17 백엔드 (WebAuthn 코어 + RP API + Admin REST API) |
| `sdk/` | TypeScript npm 패키지 (`@crosscert/passkey-sdk`) — 브라우저용 SDK |
| `docs/` | Integration guide, error code catalog, deployment guide |
| `multi-tenant-passkey-server-prd.md` | 원본 PRD |
| `multi-tenant-passkey-server-action-plan.md` | 솔로 개발 액션 플랜 |
| `spring-boot-api-response-template.md` | API Response 표준 템플릿 |

## 빠르게 시작

### 로컬 개발

```bash
cd server
docker compose up -d                                    # Postgres + Redis
./gradlew bootRun --args='--spring.profiles.active=local'
```

다른 터미널에서:
```bash
# admin user를 SQL로 직접 삽입 (콘솔 SPA는 v1.1)
docker exec -i passkey-postgres psql -U app_migrator -d passkey <<'SQL'
INSERT INTO passkey.admin_user(id, tenant_id, email, password_hash, display_name, role, status)
VALUES (gen_random_uuid(), NULL, 'ops@crosscert.local',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', -- "password"
        'Bootstrap', 'PLATFORM_OPERATOR', 'ACTIVE');
SQL

# Admin 로그인 → tenant 생성 → API key 발급 → JS SDK로 통합
curl -i -c /tmp/cookie.txt http://localhost:8080/api/v1/admin/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ops@crosscert.local","password":"password"}'

curl -i -b /tmp/cookie.txt http://localhost:8080/api/v1/admin/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"Test Card","slug":"test-card"}'
```

### SDK

```bash
cd sdk
npm install
npm run build
```

## 마일스톤 진행

| Milestone | 상태 | 산출물 |
|-----------|------|--------|
| M1 Foundation | ✅ | 멀티테넌트 데이터 모델 + RLS, 예외 인프라, 트레이스 ID |
| M2 WebAuthn Core | ✅ | webauthn4j 통합, 등록/인증 ceremony, signature counter, 자격증명 lifecycle, attestation policy |
| M3 Platform Services | ✅ | JWT, RP API key (Argon2), rate limit, audit log (partitioned + hash chain), monitoring counter |
| M4-A Customer-Facing | ✅ | Spring Security, Admin REST API, JS SDK npm 패키지 |
| M4-B Admin SPA | ⏸️ | 다음 작업 — REST API + OpenAPI 위에 React로 |
| M5 Launch Prep | ✅ | Dockerfile, prod profile, hardening, 문서 |

## 문서

- [통합 가이드](./docs/integration-guide.md) — RP 개발자용
- [에러 코드 카탈로그](./docs/error-codes.md)
- [배포 가이드](./docs/deployment.md)
- [SDK README](./sdk/README.md)
- [DB 마이그레이션 컨벤션](./server/docs/migrations.md)

## 핵심 invariants (M1+ 유지)

1. 모든 DB 접근은 `@Transactional` 안에서만
2. 모든 테넌트 스코프 테이블은 `ENABLE + FORCE ROW LEVEL SECURITY`
3. `app_runtime`은 `NOBYPASSRLS NOSUPERUSER`. `app_admin`은 `BYPASSRLS` (Platform Operator 전용)
4. 테넌트 컨텍스트 미설정 → 모든 SELECT 0 rows (fail-closed)
5. `TenantResolver`는 인터페이스 — local 헤더 / RP API key / admin session 교체 가능
6. Hibernate `getConnection(tenantId)`에서 `SET LOCAL` 단일 지점
7. `ApiResponse` envelope 모든 응답에 적용
8. RLS 정책은 `R__rls_policies.sql`로 desired-state 관리
9. URL prefix `/api/v1/rp/`, `/api/v1/admin/`, `/_diag/` 세 그룹만 허용 (ArchUnit 강제)
10. `ErrorCode`는 단일 enum + 도메인 prefix(C/A/T/P/R/D/M) + 3자리 번호

## 라이선스

Internal.
