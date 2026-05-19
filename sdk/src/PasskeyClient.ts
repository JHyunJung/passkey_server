import { base64UrlToBuffer, bufferToBase64Url } from "./base64url.js";
import type {
  ApiEnvelope,
  AuthenticateOptions,
  AuthenticateResult,
  ExcludeCredentialHint,
  ListedCredential,
  PasskeyClientOptions,
  RegisterOptions,
  RegisterResult,
} from "./types.js";

export class PasskeyApiError extends Error {
  constructor(public code: string, message: string, public envelope: unknown) {
    super(message);
    this.name = "PasskeyApiError";
  }
}

export class PasskeyClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchFn: typeof fetch;

  constructor(opts: PasskeyClientOptions) {
    if (!opts.baseUrl) throw new Error("baseUrl is required");
    if (!opts.apiKey) throw new Error("apiKey is required");
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Drives the full WebAuthn registration ceremony. Requires a user gesture. */
  async register(opts: RegisterOptions): Promise<RegisterResult> {
    const options = await this.post<{
      ceremonyId: string;
      challenge: string;
      rp: { id: string; name: string };
      user: { id: string; name: string; displayName: string };
      pubKeyCredParams: Array<{ type: string; alg: number }>;
      timeout: number;
      attestation: string;
      authenticatorSelection: {
        userVerification: string;
        residentKey: string;
        requireResidentKey: boolean;
      };
      excludeCredentials?: ExcludeCredentialHint[];
    }>("/api/v1/rp/passkeys/register/options", {
      externalUserId: opts.externalUserId,
      displayName: opts.displayName,
    });

    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: base64UrlToBuffer(options.challenge),
        rp: options.rp,
        user: {
          id: base64UrlToBuffer(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams.map((p) => ({
          type: "public-key",
          alg: p.alg,
        })),
        timeout: options.timeout,
        attestation: options.attestation as AttestationConveyancePreference,
        authenticatorSelection: {
          userVerification:
            options.authenticatorSelection.userVerification as UserVerificationRequirement,
          residentKey:
            options.authenticatorSelection.residentKey as ResidentKeyRequirement,
          requireResidentKey: options.authenticatorSelection.requireResidentKey,
        },
        // Server-side NON_EMPTY serialisation: the field is undefined for first-time enrolment.
        // Forwarding undefined to the authenticator is equivalent to omitting it.
        excludeCredentials: options.excludeCredentials?.map((c) => ({
          type: "public-key" as const,
          id: base64UrlToBuffer(c.id),
          transports: c.transports
            ? (c.transports.split(",").filter(Boolean) as AuthenticatorTransport[])
            : undefined,
        })),
      },
    })) as PublicKeyCredential | null;

    if (!cred) {
      throw new PasskeyApiError("P003", "authenticator returned no credential", null);
    }
    const attResp = cred.response as AuthenticatorAttestationResponse;

    return await this.post<RegisterResult>("/api/v1/rp/passkeys/register/verify", {
      ceremonyId: options.ceremonyId,
      credentialId: bufferToBase64Url(cred.rawId),
      clientDataJsonB64u: bufferToBase64Url(attResp.clientDataJSON),
      attestationObjectB64u: bufferToBase64Url(attResp.attestationObject),
      transports: (attResp.getTransports?.() ?? []).join(",") || undefined,
      nickname: opts.nickname,
    });
  }

  /** Drives the full WebAuthn authentication ceremony. */
  async authenticate(opts: AuthenticateOptions = {}): Promise<AuthenticateResult> {
    const options = await this.post<{
      ceremonyId: string;
      challenge: string;
      timeout: number;
      rpId: string;
      allowCredentials: Array<{ type: string; id: string; transports: string | null }>;
      userVerification: string;
    }>("/api/v1/rp/passkeys/authenticate/options", {
      externalUserId: opts.externalUserId ?? null,
    });

    const credentialReq: CredentialRequestOptions = {
      publicKey: {
        challenge: base64UrlToBuffer(options.challenge),
        timeout: options.timeout,
        rpId: options.rpId,
        userVerification:
          options.userVerification as UserVerificationRequirement,
        allowCredentials: options.allowCredentials.map((c) => ({
          type: "public-key",
          id: base64UrlToBuffer(c.id),
          transports: c.transports
            ? (c.transports.split(",").filter(Boolean) as AuthenticatorTransport[])
            : undefined,
        })),
      },
    };

    const assertion = (await navigator.credentials.get(
      credentialReq,
    )) as PublicKeyCredential | null;
    if (!assertion) {
      throw new PasskeyApiError("P004", "authenticator returned no assertion", null);
    }
    const aResp = assertion.response as AuthenticatorAssertionResponse;

    return await this.post<AuthenticateResult>(
      "/api/v1/rp/passkeys/authenticate/verify",
      {
        ceremonyId: options.ceremonyId,
        credentialId: bufferToBase64Url(assertion.rawId),
        clientDataJsonB64u: bufferToBase64Url(aResp.clientDataJSON),
        authenticatorDataB64u: bufferToBase64Url(aResp.authenticatorData),
        signatureB64u: bufferToBase64Url(aResp.signature),
        userHandleB64u: aResp.userHandle ? bufferToBase64Url(aResp.userHandle) : null,
      },
    );
  }

  /** Lists credentials registered for the given external user id. */
  async listCredentials(externalUserId: string): Promise<ListedCredential[]> {
    return await this.get<ListedCredential[]>(
      `/api/v1/rp/passkeys?externalUserId=${encodeURIComponent(externalUserId)}`,
    );
  }

  /**
   * Renames the caller's own credential. The server verifies that {@code credentialDbId} actually
   * belongs to {@code externalUserId} — IDOR defence at the application layer. RP-facing auth
   * (X-API-Key) only proves the tenant, not the end user.
   */
  async renameCredential(
    credentialDbId: string,
    externalUserId: string,
    nickname: string | null,
  ): Promise<ListedCredential> {
    return await this.patch<ListedCredential>(
      `/api/v1/rp/passkeys/${encodeURIComponent(credentialDbId)}`,
      { externalUserId, nickname },
    );
  }

  /**
   * Revokes the caller's own credential. Same ownership check as {@link renameCredential}. The
   * server burns outstanding refresh tokens for the same user on success so stale sessions cannot
   * keep refreshing access tokens after the passkey is gone.
   */
  async revokeCredential(credentialDbId: string, externalUserId: string): Promise<void> {
    await this.delete(
      `/api/v1/rp/passkeys/${encodeURIComponent(credentialDbId)}?externalUserId=${encodeURIComponent(externalUserId)}`,
    );
  }

  // ---- transport ----------------------------------------------------------

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchFn(this.baseUrl + path, {
      method: "GET",
      headers: this.defaultHeaders(),
    });
    return this.unwrap<T>(res);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await this.fetchFn(this.baseUrl + path, {
      method: "POST",
      headers: this.defaultHeaders(),
      body: JSON.stringify(body),
    });
    return this.unwrap<T>(res);
  }

  private async patch<T>(path: string, body: unknown): Promise<T> {
    const res = await this.fetchFn(this.baseUrl + path, {
      method: "PATCH",
      headers: this.defaultHeaders(),
      body: JSON.stringify(body),
    });
    return this.unwrap<T>(res);
  }

  private async delete(path: string): Promise<void> {
    const res = await this.fetchFn(this.baseUrl + path, {
      method: "DELETE",
      headers: this.defaultHeaders(),
    });
    // DELETE returns 204 No Content with an empty body — there is nothing for unwrap() to parse,
    // so we only surface non-2xx as a typed error.
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new PasskeyApiError(
        `HTTP_${res.status}`,
        text.trim().slice(0, 256) || res.statusText || "delete failed",
        { status: res.status },
      );
    }
  }

  private defaultHeaders(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-API-Key": this.apiKey,
    };
  }

  private async unwrap<T>(res: Response): Promise<T> {
    const contentType = res.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("application/json")) {
      // Non-JSON body — most commonly an HTML error page from a proxy or 5xx without our envelope.
      // Surface enough context to debug without leaking the entire body into the rejection.
      const text = await res.text().catch(() => "");
      throw new PasskeyApiError(
        `HTTP_${res.status}`,
        text.trim().slice(0, 256) || res.statusText || "non-JSON response",
        { status: res.status, contentType },
      );
    }
    let env: ApiEnvelope<T>;
    try {
      env = (await res.json()) as ApiEnvelope<T>;
    } catch (e) {
      throw new PasskeyApiError(
        `HTTP_${res.status}`,
        "invalid JSON response",
        { status: res.status, cause: e instanceof Error ? e.message : String(e) },
      );
    }
    if (!env.success) {
      throw new PasskeyApiError(
        env.code ?? "UNKNOWN",
        env.message ?? "request failed",
        env,
      );
    }
    return env.data as T;
  }
}
