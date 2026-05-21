import type * as SentryNS from "@sentry/react";

/**
 * Sentry is loaded lazily — `@sentry/react` plus the replay + tracing integrations is tens of KB
 * that the first paint never needs. {@link initSentry} defers the dynamic import to browser idle
 * time so it stays off the critical path (bundle-defer-third-party).
 *
 * <p>Because callers may fire {@link captureException} / {@link setSentryUser} before the chunk
 * has resolved, those calls are buffered and replayed once the module is ready.
 */

type SentryModule = typeof SentryNS;

/**
 * Lifecycle:
 * - `disabled` — no DSN, or {@link initSentry} not called: {@link whenReady} drops calls outright.
 * - `loading`  — DSN present, chunk import scheduled: calls are buffered into {@link pending}.
 * - `loaded`   — chunk resolved: calls run immediately; the buffer has been flushed.
 *
 * Buffering only happens in `loading`, so a disabled deployment never accumulates closures.
 */
type Status = "disabled" | "loading" | "loaded";

let status: Status = "disabled";
let sentry: SentryModule | null = null;
/** Calls made during `loading` — replayed in order once the chunk resolves, then cleared. */
const pending: Array<(s: SentryModule) => void> = [];

/**
 * Initialise Sentry from build-time env vars. No-op when {@code VITE_SENTRY_DSN} is unset, so
 * local development and air-gapped deployments stay quiet by default — in that case
 * {@link captureException} / {@link setSentryUser} are true no-ops and buffer nothing.
 *
 * <p>Wire by calling once from {@code main.tsx} before {@code <App />} mounts. The actual SDK
 * import is scheduled for browser idle time — errors that occur during the gap are buffered and
 * replayed via {@link captureException} once the chunk resolves.
 */
export function initSentry() {
  const dsn = import.meta.env.VITE_SENTRY_DSN;
  if (!dsn) {
    return;
  }
  status = "loading";
  const load = () => {
    void import("@sentry/react").then((Sentry) => {
      Sentry.init({
        dsn,
        release: import.meta.env.VITE_RELEASE ?? "passkey-admin@0.1.0",
        environment: import.meta.env.MODE,
        // Conservative sample rates — admin console traffic is tiny so 100% transactions are fine
        // and every error is worth keeping.
        tracesSampleRate: Number(import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE ?? 0.1),
        // Replay only sessions that experienced an error — minimises storage / PII surface.
        replaysSessionSampleRate: 0,
        replaysOnErrorSampleRate: Number(
          import.meta.env.VITE_SENTRY_REPLAYS_ON_ERROR_SAMPLE_RATE ?? 0.5,
        ),
        integrations: [Sentry.browserTracingIntegration(), Sentry.replayIntegration()],
        // Drop env-tagged PII before sending — emails, query strings with secrets, etc.
        beforeSend(event) {
          if (event.request?.url) {
            try {
              const u = new URL(event.request.url);
              // Anonymise any user-provided query value; keep the path so we know what page failed.
              u.search = "";
              event.request.url = u.toString();
            } catch {
              /* ignore */
            }
          }
          if (event.user) {
            // Strip email / IP — adminId is enough to correlate with audit log.
            event.user = { id: event.user.id };
          }
          return event;
        },
      });
      sentry = Sentry;
      status = "loaded";
      for (const fn of pending.splice(0)) fn(Sentry);
    });
  };

  // requestIdleCallback keeps the import off the first-paint critical path; setTimeout is the
  // fallback for Safari, which still lacks rIC.
  if (typeof window !== "undefined" && "requestIdleCallback" in window) {
    window.requestIdleCallback(load, { timeout: 4000 });
  } else {
    setTimeout(load, 2000);
  }
}

/**
 * Run `fn` against Sentry. Behaviour depends on lifecycle status:
 * - `loaded`   — invoke immediately.
 * - `loading`  — buffer for replay once the chunk resolves.
 * - `disabled` — drop the call. No buffering, so a Sentry-less deployment never leaks closures.
 */
function whenReady(fn: (s: SentryModule) => void) {
  if (status === "loaded" && sentry) fn(sentry);
  else if (status === "loading") pending.push(fn);
  // status === "disabled": intentional no-op.
}

/** Capture an exception. Buffered until the Sentry chunk loads; a no-op if the DSN is unset. */
export function captureException(
  error: unknown,
  hint?: Parameters<SentryModule["captureException"]>[1],
) {
  whenReady((s) => s.captureException(error, hint));
}

/** Set / clear the Sentry user. Buffered until the chunk loads; a no-op if the DSN is unset. */
export function setSentryUser(user: SentryNS.User | null) {
  whenReady((s) => s.setUser(user));
}
