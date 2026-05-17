/**
 * Crosscert Passkey brand glyph. SVG-only so it scales cleanly across the sidebar (26px) and any
 * future hero placement. Colors come from `--accent` so the mark follows the active theme.
 */
export function BrandMark({ size = 26 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 26 26"
      role="img"
      aria-label="Crosscert Passkey"
      style={{ flex: "none" }}
    >
      <rect width="26" height="26" rx="7" fill="var(--accent)" />
      <path
        d="M9 8.5C9 7.12 10.12 6 11.5 6h3A2.5 2.5 0 0 1 17 8.5v3a2.5 2.5 0 0 1-2.5 2.5h-1V19a1 1 0 0 1-1.7.7l-1.4-1.4-1.4 1.4A1 1 0 0 1 7.3 18.3l1.7-1.7V8.5Z"
        fill="white"
      />
    </svg>
  );
}
