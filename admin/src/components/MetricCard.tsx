import * as React from "react";
import { cn } from "@/lib/cn";

// Mirrors tokens.css .metric-label / .metric-value / .metric-delta:
//   label   → 11px uppercase 0.06em text-mute
//   value   → 28px 600 letter-tighter tabular-nums
//   delta   → 12px text-mute, optional ▲▼ colored
export function MetricCard({
  label,
  value,
  sub,
  delta,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  sub?: React.ReactNode;
  delta?: number;
  className?: string;
}) {
  return (
    <div
      className={cn("rounded-lg border p-4", className)}
      style={{
        background: "var(--surface)",
        borderColor: "var(--border-subtle)",
        boxShadow: "var(--shadow-xs)",
      }}
    >
      <div
        className="text-[11px] font-semibold uppercase"
        style={{ color: "var(--text-mute)", letterSpacing: "0.06em" }}
      >
        {label}
      </div>
      <div
        className="mt-1.5 text-[28px] font-semibold tabular-nums"
        style={{ color: "var(--text)", letterSpacing: "var(--letter-tighter)" }}
      >
        {value}
      </div>
      {(sub || typeof delta === "number") && (
        <div
          className="mt-1 text-[12px]"
          style={{ color: "var(--text-mute)" }}
        >
          {sub}
          {typeof delta === "number" && (
            <span
              className="ml-1.5"
              style={{ color: delta > 0 ? "var(--success)" : "var(--danger)" }}
            >
              {delta > 0 ? "▲" : "▼"} {Math.abs(delta)}%
            </span>
          )}
        </div>
      )}
    </div>
  );
}
