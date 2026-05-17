import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

/**
 * Tailwind v2-design-system bridge.
 * Maps Tailwind utility class names onto the OKLCH design tokens declared in `src/index.css`.
 * shadcn-style aliases (background/foreground/primary/...) stay so existing primitives keep
 * working, but every alias resolves to the design-system token under the hood.
 */
const config: Config = {
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: {
      center: true,
      padding: "1rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      colors: {
        /* Design-system surfaces & text — preferred for new code. */
        bg: "var(--bg)",
        surface: "var(--surface)",
        "surface-2": "var(--surface-2)",
        "surface-3": "var(--surface-3)",
        "surface-sunk": "var(--surface-sunk)",
        "border-subtle": "var(--border-subtle)",
        "border-strong": "var(--border-strong)",
        text: "var(--text)",
        "text-soft": "var(--text-soft)",
        "text-mute": "var(--text-mute)",
        "text-faint": "var(--text-faint)",

        /* Semantic — kept flat so `bg-info-soft`, `text-warning`, etc. resolve. */
        success: { DEFAULT: "var(--success)", soft: "var(--success-soft)", foreground: "#fff" },
        warning: { DEFAULT: "var(--warning)", soft: "var(--warning-soft)", foreground: "#1a1410" },
        danger: { DEFAULT: "var(--danger)", soft: "var(--danger-soft)", foreground: "#fff" },
        info: { DEFAULT: "var(--info)", soft: "var(--info-soft)", foreground: "#fff" },
        violet: { DEFAULT: "var(--violet)", soft: "var(--violet-soft)" },
        teal: { DEFAULT: "var(--teal)", soft: "var(--teal-soft)" },

        /* shadcn aliases re-pointed at design tokens. */
        border: "var(--border)",
        input: "var(--border)",
        ring: "var(--accent)",
        background: "var(--bg)",
        foreground: "var(--text)",
        primary: {
          DEFAULT: "var(--accent)",
          foreground: "var(--accent-fg)",
        },
        secondary: {
          DEFAULT: "var(--surface-3)",
          foreground: "var(--text)",
        },
        destructive: {
          DEFAULT: "var(--danger)",
          foreground: "#fff",
        },
        muted: {
          DEFAULT: "var(--surface-2)",
          foreground: "var(--text-mute)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          foreground: "var(--accent-fg)",
          soft: "var(--accent-soft)",
          "soft-2": "var(--accent-soft-2)",
          hover: "var(--accent-hover)",
          press: "var(--accent-press)",
        },
        card: {
          DEFAULT: "var(--surface)",
          foreground: "var(--text)",
        },
        popover: {
          DEFAULT: "var(--surface)",
          foreground: "var(--text)",
        },
      },
      borderRadius: {
        xs: "var(--radius-xs)",
        sm: "var(--radius-sm)",
        DEFAULT: "var(--radius)",
        md: "var(--radius)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
        pill: "var(--radius-pill)",
      },
      boxShadow: {
        xs: "var(--shadow-xs)",
        sm: "var(--shadow-sm)",
        md: "var(--shadow-md)",
        lg: "var(--shadow-lg)",
        focus: "var(--focus-ring)",
      },
      fontFamily: {
        sans: [
          "Geist",
          "Pretendard Variable",
          "Pretendard",
          "-apple-system",
          "BlinkMacSystemFont",
          "system-ui",
          "Roboto",
          "Helvetica Neue",
          "Segoe UI",
          "Apple SD Gothic Neo",
          "Noto Sans KR",
          "sans-serif",
        ],
        mono: [
          "Geist Mono",
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      letterSpacing: {
        tight: "var(--letter-tight)",
        tighter: "var(--letter-tighter)",
      },
      transitionTimingFunction: {
        out: "var(--ease-out)",
        "in-out": "var(--ease-in-out)",
        spring: "var(--ease-spring)",
      },
      transitionDuration: {
        fast: "var(--dur-fast)",
        DEFAULT: "var(--dur)",
        slow: "var(--dur-slow)",
      },
    },
  },
  plugins: [animate],
};

export default config;
