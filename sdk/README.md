# @crosscert/passkey-sdk

브라우저용 JavaScript SDK. Crosscert 멀티테넌트 패스키 플랫폼의 등록/인증 ceremony를 wrapping.

## 설치

```bash
npm install @crosscert/passkey-sdk
```

## 사용

```ts
import { PasskeyClient } from "@crosscert/passkey-sdk";

const client = new PasskeyClient({
  baseUrl: "https://passkey.example.com",
  apiKey: "pk_<prefix>.<secret>",
});

// 사용자 제스처 (버튼 클릭 등) 안에서:
const result = await client.register({
  externalUserId: "user-12345",
  displayName: "홍길동",
});

const session = await client.authenticate({ externalUserId: "user-12345" });
console.log(session.accessToken);
```

## ⚠️ API key 노출 주의

`apiKey`는 브라우저에 노출되면 안 됩니다. RP 백엔드가 프록시 endpoint를 만들고 거기서 `X-API-Key`를 주입하세요. `baseUrl`은 RP 백엔드의 프록시 endpoint로 설정.

## API

- `register(opts)` → `RegisterResult`
- `authenticate(opts)` → `AuthenticateResult` (JWT access/refresh 포함)
- `listCredentials(externalUserId)` → `ListedCredential[]`

자세한 type 정의는 `dist/index.d.ts` 참조.

## 빌드

```bash
npm install
npm run typecheck
npm run build  # dist/index.{js,cjs,d.ts}
```
