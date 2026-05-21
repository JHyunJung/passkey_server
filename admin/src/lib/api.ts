import axios, { AxiosError, AxiosRequestConfig, AxiosResponse } from "axios";
import { captureException } from "@/lib/sentry";
import type { ApiEnvelope, FieldError } from "@/types/api";

/**
 * Wraps an envelope failure or a transport-level error in a single shape so the UI can render
 * code + message + traceId uniformly via the toast system.
 */
export class PasskeyAdminError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly traceId?: string,
    public readonly status?: number,
    public readonly fieldErrors?: FieldError[],
  ) {
    super(message);
    this.name = "PasskeyAdminError";
  }
}

const MUTATION_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

// Hoisted: the only cookie ever read is the CSRF token, so the pattern is a fixed literal
// (js-hoist-regexp) — no per-request RegExp construction or name-escaping needed.
const XSRF_COOKIE_RE = /(?:^|;\s*)XSRF-TOKEN=([^;]*)/;

function readXsrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const match = document.cookie.match(XSRF_COOKIE_RE);
  return match ? decodeURIComponent(match[1]!) : undefined;
}

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
  withCredentials: true,
  timeout: 15_000,
  headers: { "Content-Type": "application/json", Accept: "application/json" },
});

/** Echo the XSRF-TOKEN cookie value into the X-XSRF-TOKEN header on mutation requests. */
api.interceptors.request.use((config) => {
  if (config.method && MUTATION_METHODS.has(config.method.toUpperCase())) {
    const token = readXsrfToken();
    if (token) {
      config.headers = config.headers ?? {};
      (config.headers as Record<string, string>)["X-XSRF-TOKEN"] = token;
    }
  }
  return config;
});

/**
 * Lifted out so the bootstrap (main.tsx) can wire the live `QueryClient` instance in. Avoids a
 * circular import between api.ts and the query client module.
 */
type Unauthorised = () => void;
let onUnauthorised: Unauthorised = () => {};
export function setUnauthorisedHandler(fn: Unauthorised) {
  onUnauthorised = fn;
}

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiEnvelope<unknown>>) => {
    if (error.response?.status === 401) {
      onUnauthorised();
    }
    const adminError = toAdminError(error);
    // 5xx / network errors → Sentry. 4xx (validation, auth) are user-visible via toast already.
    const status = error.response?.status ?? 0;
    if (!error.response || status >= 500) {
      captureException(adminError, {
        tags: { http_status: String(status || "network") },
        extra: { traceId: adminError.traceId, code: adminError.code },
      });
    }
    return Promise.reject(adminError);
  },
);

function toAdminError(error: AxiosError<ApiEnvelope<unknown>>): PasskeyAdminError {
  const status = error.response?.status;
  const envelope = error.response?.data;
  const traceId = envelope?.traceId;
  if (envelope && typeof envelope === "object" && "code" in envelope) {
    return new PasskeyAdminError(
      envelope.code ?? "UNKNOWN",
      envelope.message ?? "request failed",
      traceId,
      status,
      envelope.error?.fieldErrors,
    );
  }
  // Transport / non-JSON error.
  return new PasskeyAdminError(
    status ? `HTTP_${status}` : "NETWORK_ERROR",
    error.message || "network error",
    undefined,
    status,
  );
}

/**
 * Unwraps the {@link ApiEnvelope} after a successful HTTP call. Throws a {@link PasskeyAdminError}
 * for envelope-level failures (success=false) — these come through with HTTP 200 in some flows
 * (e.g. validation aggregations).
 */
export function unwrap<T>(response: AxiosResponse<ApiEnvelope<T>>): T {
  const env = response.data;
  if (!env || env.success !== true) {
    throw new PasskeyAdminError(
      env?.code ?? "UNKNOWN",
      env?.message ?? "request failed",
      env?.traceId,
      response.status,
      env?.error?.fieldErrors,
    );
  }
  // Some endpoints return ApiResponse.ok() with data=null (e.g. logout).
  return env.data as T;
}

export async function apiGet<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
  return unwrap<T>(await api.get<ApiEnvelope<T>>(path, config));
}
export async function apiPost<T>(
  path: string,
  body?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  return unwrap<T>(await api.post<ApiEnvelope<T>>(path, body, config));
}
export async function apiPut<T>(
  path: string,
  body?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  return unwrap<T>(await api.put<ApiEnvelope<T>>(path, body, config));
}
export async function apiPatch<T>(
  path: string,
  body?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  return unwrap<T>(await api.patch<ApiEnvelope<T>>(path, body, config));
}
export async function apiDelete<T = void>(
  path: string,
  config?: AxiosRequestConfig,
): Promise<T> {
  return unwrap<T>(await api.delete<ApiEnvelope<T>>(path, config));
}
