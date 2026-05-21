/** Truncate a long identifier showing only its last N characters with an ellipsis prefix. */
export function lastN(value: string | null | undefined, n: number = 8): string {
  if (!value) return "—";
  return value.length <= n ? value : `…${value.slice(-n)}`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatPercent(numerator: number, denominator: number): string {
  if (denominator <= 0) return "—";
  return `${((numerator / denominator) * 100).toFixed(1)}%`;
}

// Hoisted to module scope (js-cache-function-results) — Intl.NumberFormat construction parses
// locale data, so building it once and reusing it beats a per-call `new` in any render path.
const COUNT_FORMATTER = new Intl.NumberFormat("ko-KR");

/** Format an integer count with ko-KR thousands separators. */
export function formatCount(n: number): string {
  return COUNT_FORMATTER.format(n);
}

/** Like {@link formatCount} but renders an em-dash for an absent value. */
export function formatMaybeCount(n: number | null | undefined): string {
  return n === null || n === undefined ? "—" : formatCount(n);
}
