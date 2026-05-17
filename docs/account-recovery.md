# Account Recovery — Passkey Server 운영 절차

> 사용자가 디바이스/credential을 잃었거나, 사고가 의심되거나, 운영자가 강제로 회수해야 할 때의 표준 절차. v1.0.

## 1. 시나리오와 1차 대응

| 시나리오 | 1차 액션 | 권장 reason | 후속 |
|----------|---------|-------------|------|
| **S1. 사용자가 단말 1개를 잃음 (다른 단말 보유)** | 사용자 본인이 RP 화면에서 잃은 credential을 삭제 (`DELETE /api/v1/rp/passkeys/{id}`) | `USER_REQUEST` | 다른 단말로 재로그인 후 새 credential 추가 |
| **S2. 사용자가 모든 단말을 잃음** | RP CS가 사용자 신원확인 후 **RP_ADMIN이 admin console에서 모든 credential을 revoke** | `ADMIN_FORCED` | RP의 fallback 인증(예: 기존 ID/PW + OTP)으로 재로그인 → 신규 credential 등록 |
| **S3. credential 유출/훔침 의심** | RP_ADMIN이 즉시 해당 credential 1개 revoke | `COMPROMISE_SUSPECTED` | audit log에서 그 credential의 최근 인증 history 확인. 필요 시 사용자 알림 |
| **S4. 시스템이 자동 감지 (signature counter regression)** | `AuthenticationService`가 자동으로 credential을 revoke | `SIGNATURE_COUNTER_REGRESSION` | `audit.signature_counter.regression` ERROR 로그 + Prometheus alert. CS가 사용자에게 안내 |
| **S5. RP 사고로 credential 일괄 회수** | PLATFORM_OPERATOR가 SQL 또는 admin endpoint로 일괄 호출 | `ADMIN_FORCED` | 사용자 안내 메일 / 공지 |

## 2. 회수 시 자동으로 일어나는 일

`CredentialLifecycleService.revoke(id, reason)` 한 번 호출 시:

1. `credential.status = REVOKED`, `revoked_at = now()`, `revoked_reason = <reason>`
2. **그 사용자의 모든 활성 refresh token이 함께 회수**됨 (`RevokedReason.CREDENTIAL_REVOKED`).
3. Audit row가 `CREDENTIAL_REVOKED` event로 기록됨 (payload에 `reason`, `refreshTokensRevoked` 카운트).
4. **다음 인증 시도부터 즉시 차단** — credential 검사가 `isActive() == false`이므로 `CREDENTIAL_REVOKED` (P007) 응답.
5. 이미 발급된 access token은 TTL(15분) 내 유효. 그 이후엔 refresh도 막혀 있으므로 자동 끊김.

**SLA**: revoke API 호출 → 다음 verify 호출이 401 받기까지 ≤ 5초 (Redis pub/sub 통해 cache evict + DB row 즉시 반영).

## 3. 사용자에게 보여줄 메시지 (RP CS 가이드)

| reason | 사용자 안내 문구 |
|--------|------------------|
| `USER_REQUEST` | "회원님께서 직접 삭제하신 패스키입니다. 새 패스키를 등록하시려면 로그인 후 [내 보안 설정]에서 추가하세요." |
| `ADMIN_FORCED` | "보안 정책에 따라 운영자가 패스키를 회수했습니다. 본인 확인 후 새 패스키를 등록할 수 있습니다." |
| `COMPROMISE_SUSPECTED` | "비정상적인 사용 정황이 감지되어 패스키를 안전상의 이유로 회수했습니다. 즉시 본인 확인 후 새 패스키 등록을 권장합니다." |
| `SIGNATURE_COUNTER_REGRESSION` | "패스키의 보안 카운터에서 이상이 감지되어 자동으로 회수되었습니다. 이는 다른 기기에서의 복제 시도일 수 있습니다. 새 패스키를 등록하기 전 기기 보안을 점검해 주세요." |
| `LIFECYCLE_EXPIRED` | "정해진 보유 기간이 지나 패스키가 자동 만료되었습니다. 새로 등록해 주세요." |

## 4. RP가 관리자 화면 없이 RP CS만으로 처리하려면

RP는 자체 백엔드에서 다음을 호출 가능 (X-API-Key 보유):

```
DELETE /api/v1/rp/passkeys/{id}      # USER_REQUEST 자동 기록
```

서버 로그에 `credential.revoke ... reason=USER_REQUEST` 기록.

## 5. 운영자 (PLATFORM_OPERATOR / RP_ADMIN) 화면에서 처리하려면

Admin console → Tenant Detail → **Credentials** 탭 → 해당 행 [회수] → reason select → 확인.

API:
```
DELETE /api/v1/admin/tenants/{tenantId}/credentials/{credentialId}?reason=COMPROMISE_SUSPECTED
```

화면에 reason select가 보이지 않으면 v1.1로 미반영 — 그 경우 reason은 `ADMIN_FORCED` 기본값.

## 6. 사고 후 forensics

```sql
-- 특정 credential의 lifecycle
SELECT id, status, revoked_at, revoked_reason, last_used_at, signature_counter
  FROM passkey.credential
 WHERE id = '<credentialId>';

-- 그 credential의 최근 audit
SELECT created_at, event_type, actor_type, actor_id, payload
  FROM passkey.audit_log
 WHERE tenant_id = '<tenantId>'
   AND subject_id = '<credentialId>'
 ORDER BY created_at DESC
 LIMIT 50;

-- 그 사용자의 회수된 refresh token 이력 (사고 시 어떤 세션이 살아있었는지)
SELECT jti, issued_at, revoked_at, revoked_reason, client_ip, user_agent
  FROM passkey.refresh_token
 WHERE tenant_user_id = '<userId>'
 ORDER BY issued_at DESC
 LIMIT 20;
```

`pg_advisory_xact_lock` 기반 audit hash chain은 임의 조작 시 다음 일별 `AuditChainScheduler`가 자동 탐지.

## 7. 정책 권장값

| 정책 | 권장 default | 변경 시 영향 |
|------|-------------|--------------|
| Refresh token TTL | 30일 (`PASSKEY_JWT_REFRESH_TTL`) | 짧게 줄이면 앱이 자주 재로그인 요구 |
| Access token TTL | 15분 | 짧을수록 회수 SLA 보장 강함 |
| Per-credential rate limit | 10/분 | 너무 낮으면 정상 사용자도 lockout |
| `allowSyncable` | tenant 정책에 따라 | 금융권/공공: false 권장. B2C: true 권장 |
| `residentKey` | `PREFERRED` | username-less 흐름이 핵심이면 `REQUIRED`, 그 외 `PREFERRED` |

## 8. v1.1 이후

- **passwordless recovery 토큰**: 임시 가입용 1회용 코드 발급 (이메일/SMS 통해)
- **RP-side webhook**: revoke 발생 시 RP에 비동기 통지
- **사용자별 token reuse 통계**: REUSE_DETECTED 빈도 → 자동 알람
