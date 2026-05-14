# RP Integration Guide

이 문서는 Relying Party (RP) 개발자가 Crosscert Passkey 플랫폼을 자기 서비스에 통합하는 절차를 단계별로 설명합니다. 어드민 콘솔에서 tenant가 이미 생성되어 있고 RP ID/origin이 설정됐다고 가정합니다.

## 1. 사전 준비

| 항목 | 비고 |
|------|------|
| Platform Base URL | 예: `https://passkey.example.com` |
| RP API Key | 어드민 콘솔의 "API Keys"에서 발급. 발급 직후 plaintext 1회만 표시됨. `pk_<prefix>.<secret>` 형식. **반드시 안전한 시크릿 저장소에 보관.** |
| RP ID | WebAuthn 스펙상 RP ID는 origin의 effective domain. 예: origin `https://app.card.co.kr` → RP ID `card.co.kr` 또는 `app.card.co.kr`. 어드민 콘솔에 설정된 값과 일치해야 함. |
| Origins | 허용된 origin들의 CSV. 예: `https://app.card.co.kr,https://www.card.co.kr` |

## 2. 통합 옵션

### 옵션 A — JS SDK 사용 (권장)

```bash
npm install @crosscert/passkey-sdk
```

```ts
import { PasskeyClient } from "@crosscert/passkey-sdk";

const client = new PasskeyClient({
  baseUrl: "https://passkey.example.com",
  apiKey: import.meta.env.VITE_PASSKEY_API_KEY,
});

// 등록 (사용자 제스처 안에서)
const result = await client.register({
  externalUserId: "user-12345",
  displayName: "홍길동",
  nickname: "iPhone 15",
});

// 인증
const session = await client.authenticate({ externalUserId: "user-12345" });
// session.accessToken 을 자기 서비스의 인증 토큰으로 사용
```

⚠️ **API key는 브라우저에 노출하면 절대 안 됩니다.** RP의 백엔드가 프록시해야 함:

```
브라우저 → RP 백엔드 (cookie/세션 인증) → Crosscert Passkey API (X-API-Key)
```

SDK의 `baseUrl`을 RP 백엔드의 프록시 endpoint로 설정하고, RP 백엔드에서 `X-API-Key` 헤더를 주입합니다.

### 옵션 B — REST API 직접 호출

#### 등록 — Step 1: Options
```http
POST /api/v1/rp/passkeys/register/options
X-API-Key: pk_<prefix>.<secret>
Content-Type: application/json

{
  "externalUserId": "user-12345",
  "displayName": "홍길동"
}
```

Response:
```json
{
  "success": true,
  "code": "OK",
  "data": {
    "ceremonyId": "uuid",
    "challenge": "base64url",
    "rp": { "id": "card.co.kr", "name": "Card Company" },
    "user": { "id": "base64url", "name": "user-12345", "displayName": "홍길동" },
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "attestation": "none",
    "authenticatorSelection": {
      "userVerification": "preferred",
      "residentKey": "preferred",
      "requireResidentKey": false
    }
  }
}
```

#### 등록 — Step 2: navigator.credentials.create
브라우저가 위 옵션으로 `navigator.credentials.create({ publicKey: ... })` 호출 (`challenge` 등의 base64url 필드를 `ArrayBuffer`로 변환 필요).

#### 등록 — Step 3: Verify
```http
POST /api/v1/rp/passkeys/register/verify
X-API-Key: ...

{
  "ceremonyId": "<step1 ceremonyId>",
  "credentialId": "base64url(rawId)",
  "clientDataJsonB64u": "base64url(clientDataJSON)",
  "attestationObjectB64u": "base64url(attestationObject)",
  "transports": "internal,hybrid",
  "nickname": "iPhone 15"
}
```

#### 인증 — 같은 패턴: `/options` → `navigator.credentials.get` → `/verify`

성공 시 `accessToken` (JWT) + `refreshToken` 반환. RP 서비스는 이 토큰을 자기 세션으로 사용하거나 자기 토큰으로 교환.

## 3. 통합 체크리스트

- [ ] 어드민 콘솔에서 tenant 생성, RP ID/origin 설정 완료
- [ ] API Key 발급, RP 백엔드의 시크릿 저장소에 보관
- [ ] HTTPS 활성화 (WebAuthn은 secure context 필수)
- [ ] 등록 ceremony 한 번 성공
- [ ] 인증 ceremony 한 번 성공 후 토큰 검증
- [ ] 사용자가 패스키 삭제 → 다음 인증이 실패하는 흐름 확인
- [ ] 사용자가 두 개 등록 → 한 디바이스 잃어도 다른 디바이스로 인증 가능 확인 (recovery)
- [ ] 등록/인증 실패 응답에서 `code`로 분기 (P003, P004, P005 등)

## 4. 다음 단계

- 에러 코드 카탈로그: [error-codes.md](./error-codes.md)
- API 전체 reference: 서버에 부팅 후 `/swagger-ui/index.html` (OpenAPI 자동 생성)
- 배포 가이드: [deployment.md](./deployment.md)
