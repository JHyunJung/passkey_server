export interface ApiEnvelope<T> {
  success: boolean;
  code: string;
  message: string;
  data?: T;
  error?: {
    errorCode: string;
    fieldErrors?: Array<{ field: string; rejectedValue: unknown; reason: string }>;
  };
  traceId?: string;
  timestamp: string;
}

export interface PasskeyClientOptions {
  /** Platform base URL, e.g. https://passkey.example.com */
  baseUrl: string;
  /** RP API key issued by the admin console (pk_<prefix>.<secret>). */
  apiKey: string;
  /** Optional fetch override for testing/SSR. */
  fetch?: typeof fetch;
}

export interface RegisterOptions {
  externalUserId: string;
  displayName: string;
  /** Optional nickname stored on the credential row. */
  nickname?: string;
}

export interface RegisterResult {
  credentialDbId: string;
  credentialId: string;
  aaguid: string | null;
}

export interface AuthenticateOptions {
  /** Optional — when omitted, discoverable-credential flow is used. */
  externalUserId?: string;
}

export interface AuthenticateResult {
  credentialDbId: string;
  tenantUserId: string;
  credentialId: string;
  signatureCounter: number;
  accessToken: string;
  refreshToken: string;
  accessExpiresIn: number;
}

export interface ListedCredential {
  id: string;
  tenantUserId: string;
  credentialId: string;
  nickname: string | null;
  status: "ACTIVE" | "REVOKED";
  aaguid: string | null;
  transports: string | null;
  signatureCounter: number;
  lastUsedAt: string | null;
  createdAt: string;
}
