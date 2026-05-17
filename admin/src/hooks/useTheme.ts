import * as React from "react";

type Theme = "light" | "dark";
const STORAGE_KEY = "passkey-admin-theme";

function readInitial(): Theme {
  if (typeof window === "undefined") return "light";
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyToRoot(theme: Theme) {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = theme;
}

/**
 * Reactive light/dark switch that drives the `data-theme` attribute on the html root. The CSS
 * variables in `src/index.css` flip on that selector, so every token-aware surface picks up the
 * change in the same paint.
 */
export function useTheme(): [Theme, (next?: Theme) => void] {
  const [theme, setTheme] = React.useState<Theme>(() => {
    const initial = readInitial();
    applyToRoot(initial);
    return initial;
  });

  const toggle = React.useCallback((next?: Theme) => {
    setTheme((curr) => {
      const value = next ?? (curr === "light" ? "dark" : "light");
      applyToRoot(value);
      try {
        window.localStorage.setItem(STORAGE_KEY, value);
      } catch {
        /* private mode — keep the in-memory state only. */
      }
      return value;
    });
  }, []);

  return [theme, toggle];
}
