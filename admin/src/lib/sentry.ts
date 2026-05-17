import * as Sentry from "@sentry/react";

/**
 * Initialise Sentry from build-time env vars. No-op when {@code VITE_SENTRY_DSN} is unset, so
 * local development and air-gapped deployments stay quiet by default.
 *
 * <p>Wire by calling once from {@code main.tsx} before {@code <App />} mounts. Errors that bubble
 * out of React render are captured via {@link Sentry.ErrorBoundary}; ad-hoc capture is available
 * through {@link Sentry.captureException}.
 */
export function initSentry() {
  const dsn = import.meta.env.VITE_SENTRY_DSN;
  if (!dsn) {
    return;
  }
  Sentry.init({
    dsn,
    release: import.meta.env.VITE_RELEASE ?? "passkey-admin@0.1.0",
    environment: import.meta.env.MODE,
    // Conservative sample rates — admin console traffic is tiny so 100% transactions are fine and
    // every error is worth keeping.
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
}

/** Re-export so callers don't depend on @sentry/react directly. */
export const SentryErrorBoundary = Sentry.ErrorBoundary;
export const captureException = Sentry.captureException;
export const setSentryUser = Sentry.setUser;
