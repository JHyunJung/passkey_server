import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { AppToastProvider } from "@/hooks/useToast";
import { ME_KEY } from "@/hooks/useMe";
import { setUnauthorisedHandler } from "@/lib/api";
import { ErrorBoundary } from "@/lib/ErrorBoundary";
import { initSentry } from "@/lib/sentry";
import "./index.css";

initSentry();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: (failureCount, error) => {
        const status = (error as { status?: number } | undefined)?.status;
        if (status === 401 || status === 403 || status === 404) return false;
        return failureCount < 1;
      },
      refetchOnWindowFocus: false,
    },
  },
});

setUnauthorisedHandler(() => {
  // Cache null instead of removing — removeQueries causes the useMe observer to immediately
  // re-fetch, which loops against the same 401 and quickly burns the rate-limit bucket.
  queryClient.setQueryData(ME_KEY, null);
  if (typeof window !== "undefined" && window.location.pathname !== "/") {
    window.location.assign("/");
  }
});

function FatalErrorFallback({ resetError }: { resetError: () => void }) {
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-4 px-6 text-center">
      <h1 className="text-xl font-semibold">예기치 않은 오류가 발생했습니다.</h1>
      <p className="max-w-md text-sm text-muted-foreground">
        문제가 자동으로 보고되었습니다. 페이지를 새로 고침하거나 잠시 후 다시 시도해 주세요.
      </p>
      <button
        type="button"
        className="rounded-md border px-4 py-2 text-sm hover:bg-accent"
        onClick={() => {
          resetError();
          window.location.reload();
        }}
      >
        새로고침
      </button>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary fallback={({ resetError }) => <FatalErrorFallback resetError={resetError} />}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AppToastProvider>
            <App />
          </AppToastProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
