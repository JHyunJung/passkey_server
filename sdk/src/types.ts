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

/**
 * Hint to the authenticator that these credentials are already enrolled for the user. The server
 * derives this list from the user's active credentials and includes it in the registration options
 * payload. The SDK forwards it to `navigator.credentials.create()` so a duplicate enrolment
 * attempt surfaces as `InvalidStateError` on the client instead of a server-side conflict.
 */
export interface ExcludeCredentialHint {
  type: string;
  id: string;
  transports: string | null;
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
