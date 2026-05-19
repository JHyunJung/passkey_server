# Error Code Catalog

모든 응답은 `ApiResponse<T>` envelope로 통일됩니다. 실패 응답은:

```json
{
  "success": false,
  "code": "T001",
  "message": "Tenant not found",
  "error": {
    "errorCode": "T001",
    "fieldErrors": [ /* validation 실패 시만 */ ]
  },
  "traceId": "a1b2c3d4e5f6g7h8",
  "timestamp": "2026-05-15T03:29:26.215Z"
}
```

응답 헤더에 `X-Trace-Id`가 echo되어 클라이언트 로그와 서버 로그를 매칭 가능.

## Prefix 규칙

| Prefix | 도메인 |
|--------|--------|
| `C` | Common (검증 실패, 메서드 미지원 등) |
| `A` | Auth (RP API key, JWT, admin login) |
| `T` | Tenant |
| `P` | Passkey / Credential (WebAuthn ceremony) |
| `R` | Rate-limit |
| `D` | Audit |
| `M` | Admin |

## 코드 목록

### Common (C)
| Code | HTTP | Message |
|------|------|---------|
| `C001` | 400 | Invalid input value |
| `C002` | 405 | Method not allowed |
| `C003` | 404 | Entity not found |
| `C004` | 400 | Required parameter missing |
| `C005` | 400 | Type mismatch |
| `C999` | 500 | Server error |

### Auth (A)
| Code | HTTP | Message | 처리 |
|------|------|---------|------|
| `A001` | 401 | Authentication required | 토큰 추가 후 재시도 |
| `A002` | 403 | Access denied | 권한 부족 |
| `A003` | 401 | Token expired | refresh token으로 재발급 |
| `A004` | 401 | Invalid token | 재로그인 |
| `A005` | 401 | Invalid API key | API key 확인, 재발급 검토 |
| `A010` | 401 | Admin login required | 어드민 콘솔 로그인 |

### Tenant (T)
| Code | HTTP | Message |
|------|------|---------|
| `T001` | 404 | Tenant not found |
| `T002` | 403 | Tenant is not active |
| `T003` | 400 | Tenant context is required (X-API-Key 또는 X-Tenant-Id 누락) |
| `T004` | 409 | Tenant slug already exists |

### Passkey (P)
| Code | HTTP | Message | 처리 |
|------|------|---------|------|
| `P001` | 404 | WebAuthn configuration is missing | 어드민에서 RP ID/origin 설정 |
| `P002` | 400 | Challenge expired or not found | 5분 초과 또는 ceremonyId 재사용. options 다시 발급 후 retry |
| `P003` | 400 | Attestation verification failed | clientData/origin/challenge 불일치 점검 |
| `P004` | 400 | Assertion verification failed | 위와 동일 |
| `P005` | 401 | Signature counter regression detected | **클론 의심.** 사용자에게 자격증명 폐기 + 재등록 안내 |
| `P006` | 404 | Credential not found | 등록되지 않은 credentialId |
| `P007` | 401 | Credential is revoked | 삭제된 자격증명으로 인증 시도 |
| `P008` | 403 | Authenticator AAGUID not allowed | tenant attestation policy의 allowlist 확인 |
| `P009` | 400 | Origin not in tenant allowlist | 콘솔에서 origin 추가 또는 호출 origin 수정 |
| `P010` | 403 | Attestation trust chain validation failed | strict tenant — authenticator AAGUID가 MDS BLOB에 없음. 해당 키 차단 또는 BLOB refresh 후 재시도 |
| `P011` | 503 | MDS service unavailable for strict tenant | 서버 `passkey.mds.enabled=false` 또는 BLOB 첫 fetch 실패. `/_diag/mds-status` 확인 후 인프라 점검 |
| `P012` | 403 | Authenticator has been revoked or compromised | FIDO StatusReport REVOKED/COMPROMISED. **사용자에게 즉시 폐기 + 재등록 안내** |
| `P013` | 403 | Syncable / backup-eligible authenticator not allowed | tenant 정책이 `allowSyncable=false`인데 BE(Backup Eligible) flag가 set된 authenticator로 등록 시도. iCloud Keychain / Google Password Manager 계열 차단 시 발생 |
| `P014` | 409 | FIDO MDS is disabled on this deployment | 서버 `passkey.mds.enabled=false` 상태에서 strict 전용 admin 작업 호출 |
| `P015` | 502 | Failed to refresh FIDO MDS metadata | BLOB 다운로드/검증 실패 — root CA 만료, 네트워크, BLOB 서명 변경 등. `/_diag/mds-status` + scheduler 로그 확인 |

#### `P005 SIGNATURE_COUNTER_REGRESSION` 세부 reason

서버는 regression의 사유를 BusinessException detail + 로그 + audit payload의 `reason` 필드에 실어 보냅니다. **응답 코드는 모두 P005로 동일**하지만 운영자가 page 우선순위를 가를 수 있도록 다음 세 가지로 구분합니다:

| reason | 조건 | 해석 |
|--------|------|------|
| `DOWNGRADE_TO_ZERO` | `stored > 0` 이고 `new == 0` | 가장 강한 clone 시그널 (또는 firmware reset). 자동 revoke. |
| `REPLAY`            | `stored == new`            | 카운터가 전진하지 않음 — replay / relay 가능성. 자동 revoke. |
| `BACKWARDS`         | `0 < new < stored`         | 클래식 clone (정상 키는 절대 감소하지 않음). 자동 revoke. |

`auth.signature_counter.regression` ERROR 로그에 `reason=...` 필드로 출력, `passkey.signature_counter_regression` counter는 합산. reason별 분리가 필요하면 별도 알람 룰에서 로그 필터링.

#### Credential ownership note (P006 vs IDOR)

`/api/v1/rp/passkeys` 의 `PATCH /{id}` / `DELETE /{id}` 는 호출한 RP의 end-user가 해당 credential의 실제 소유자인지를 서버가 검증합니다. 다른 사용자의 credentialId를 시도하면 **존재성 leak 방지를 위해 `P006 Credential not found`** 로 응답합니다 (실제로 존재해도 동일). 서버 로그에는 `credential.ownership.mismatch` WARN + Prometheus counter `passkey.security.ownership_mismatch` 가 증가하므로 운영팀은 반복 시도를 알람으로 감지할 수 있습니다.

### Rate-limit (R)
| Code | HTTP | Message |
|------|------|---------|
| `R001` | 429 | Rate limit exceeded |

### Audit (D)
| Code | HTTP | Message |
|------|------|---------|
| `D001` | 500 | Audit hash chain integrity violation |

### Admin (M)
| Code | HTTP | Message |
|------|------|---------|
| `M001` | 404 | Admin user not found |
| `M002` | 403 | Admin role does not permit this action |

## 신뢰할 수 있는 patterns

- `code`만으로 분기 (HTTP status는 변경 가능성 있음, code는 stable 계약)
- `traceId`를 로그에 남겨두면 서버 측에서 동일 traceId로 grep 가능
- 5xx 응답은 자동 재시도 가능 (idempotent 한 endpoint만)
- 4xx 응답은 자동 재시도하지 말 것 — 입력 수정 후 재시도
