# Account Recovery — Passkey Server 운영 절차

> 사용자가 디바이스/credential을 잃었거나, 사고가 의심되거나, 운영자가 강제로 회수해야 할 때의 표준 절차. v1.0.

## 1. 시나리오와 1차 대응

| 시나리오 | 1차 액션 | 권장 reason | 후속 |
|----------|---------|-------------|------|
| **S1. 사용자가 단말 1개를 잃음 (다른 단말 보유)** | 사용자 본인이 RP 화면에서 잃은 credential을 삭제 (`DELETE /api/v1/rp/passkeys/{id}?externalUserId=<id>` — v0.2.0부터 ownership 검증) | `USER_REQUEST` | 다른 단말로 재로그인 후 새 credential 추가 |
| **S2. 사용자가 모든 단말을 잃음** | RP CS가 사용자 신원확인 후 **RP_ADMIN이 admin console에서 모든 credential을 revoke** | `ADMIN_FORCED` | RP의 fallback 인증(예: 기존 ID/PW + OTP)으로 재로그인 → 신규 credential 등록 |
| **S3. credential 유출/훔침 의심** | RP_ADMIN이 즉시 해당 credential 1개 revoke | `COMPROMISE_SUSPECTED` | audit log에서 그 credential의 최근 인증 history 확인. 필요 시 사용자 알림 |
| **S4. 시스템이 자동 감지 (signature counter regression)** | `AuthenticationService`가 자동으로 credential을 revoke | `SIGNATURE_COUNTER_REGRESSION` | `audit.signature_counter.regression` ERROR 로그 + Prometheus alert. **로그/audit의 `reason` 필드로 세부 유형 (`DOWNGRADE_TO_ZERO` / `REPLAY` / `BACKWARDS`) 확인 후** CS가 사용자에게 안내. 세부 분석은 §6 참조 |
| **S5. RP 사고로 credential 일괄 회수** | PLATFORM_OPERATOR가 SQL 또는 admin endpoint로 일괄 호출 | `ADMIN_FORCED` | 사용자 안내 메일 / 공지 |
| **S6. CTAP 2.1 BS flag flip — 사용자가 새 디바이스 백업 활성화** | 자동 — `AuthenticationService`가 BS=false→true 감지 시 `CREDENTIAL_BACKUP_STATE_CHANGED` audit + `auth.backup_state.synced` WARN | 자동 audit (revoke 아님) | 컴플라이언스 RP는 audit 구독 후 자체 정책으로 trust downgrade 결정. 서버는 자동 차단하지 않음 |

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
DELETE /api/v1/rp/passkeys/{id}?externalUserId=<userId>      # USER_REQUEST 자동 기록
```

> **v0.2.0 BREAKING**: `externalUserId` query param이 필수입니다. 서버가 ownership을 검증하므로 다른 사용자의 credentialId UUID를 추측해 삭제하려는 시도는 `P006 Credential not found`로 응답되고, `credential.ownership.mismatch` WARN 로그 + Prometheus counter `passkey.security.ownership_mismatch` 가 증가합니다.

서버 로그:
- 성공: `credential.revoke.rp tenantId=… tenantUserId=… credentialDbId=… externalUserId=…`
- 이어서: `credential.revoke … reason=USER_REQUEST refreshTokensRevoked=…` (doRevoke 본체)

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

> 인프라 노트: v1.5에서 PostgreSQL → Oracle 19c로 이식하며 audit hash chain은 `DBMS_LOCK.ALLOCATE_UNIQUE + DBMS_LOCK.REQUEST(X_MODE, release_on_commit=TRUE)` 로 바뀌었습니다 (구 `pg_advisory_xact_lock`). 임의 조작 시 다음 일별 `AuditChainScheduler`가 여전히 자동 탐지.

### 6.1 SIGNATURE_COUNTER_REGRESSION reason 분석

자동 revoke된 credential의 audit row payload에 `reason` 필드가 들어 있습니다. 같은 P005 응답이지만 page 우선순위가 다릅니다:

| reason | 1차 해석 | 추가 확인 |
|--------|---------|----------|
| `DOWNGRADE_TO_ZERO` | 가장 강한 clone 시그널 또는 authenticator firmware reset | 사용자에게 디바이스 변경 여부 확인. 펌웨어 reset이면 단발성이라 재등록으로 해결 |
| `REPLAY`            | 카운터 진전 없음 — relay/replay 또는 두 디바이스 동시 사용 | 같은 시간대 동일 credential의 인증 audit가 두 IP에 분포하는지 확인 |
| `BACKWARDS`         | 클래식 clone (counter 역행)        | 거의 항상 악성. 사용자 알림 + 다른 credential 점검 |

```sql
-- 최근 7일 regression의 reason 분포
SELECT TO_CHAR(created_at, 'YYYY-MM-DD') AS d,
       JSON_VALUE(payload, '$.reason') AS reason,
       COUNT(*) AS n
  FROM passkey.audit_log
 WHERE event_type = 'SIGNATURE_COUNTER_REGRESSION'
   AND created_at > SYSTIMESTAMP - INTERVAL '7' DAY
 GROUP BY TO_CHAR(created_at, 'YYYY-MM-DD'), JSON_VALUE(payload, '$.reason')
 ORDER BY 1 DESC, 3 DESC;
```

### 6.2 Backup state flip 추적

```sql
-- 지난 24시간 동안 클라우드 백업으로 전환된(SYNCED) credentials
SELECT created_at, subject_id, JSON_VALUE(payload, '$.credentialId') AS cred
  FROM passkey.audit_log
 WHERE event_type = 'CREDENTIAL_BACKUP_STATE_CHANGED'
   AND JSON_VALUE(payload, '$.direction') = 'SYNCED'
   AND created_at > SYSTIMESTAMP - INTERVAL '1' DAY;
```

Prometheus: `rate(passkey_backup_state_flips_total{direction="synced"}[1h])`.

### 6.3 IDOR / 크로스테넌트 시그널

| 메트릭 | 의미 | 알람 임계 (예) |
|--------|------|---------------|
| `passkey.security.ownership_mismatch` | RP가 다른 사용자의 credentialId로 rename/revoke 시도 | 5분 내 10건↑ |
| `passkey.security.refresh_tid_mismatch` | tenant A 발급 refresh token이 tenant B의 API key로 들어옴 | 1건이라도 즉시 page |
| `passkey.security.refresh_reuse_detected` | 이미 rotate된 refresh token 재제출 → family burn | 5분 내 3건↑ |

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
