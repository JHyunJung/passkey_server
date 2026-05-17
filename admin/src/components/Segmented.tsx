import { cn } from "@/lib/cn";

// Pill-tab style toggle group. Mirrors the handoff Segmented:
//   inline-flex container with --surface-3 bg + --border, 3px inner padding;
//   active item gets a --surface card with shadow-sm.
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  className,
}: {
  value: T;
  onChange: (next: T) => void;
  options: ReadonlyArray<T>;
  className?: string;
}) {
  return (
    <div
      className={cn("inline-flex flex-wrap rounded-md border p-[3px]", className)}
      style={{ background: "var(--surface-3)", borderColor: "var(--border)" }}
      role="tablist"
    >
      {options.map((o) => {
        const active = o === value;
        return (
          <button
            key={o}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(o)}
            className="rounded-sm px-2.5 py-1 font-mono text-[11px] transition-colors"
            style={{
              background: active ? "var(--surface)" : "transparent",
              color: active ? "var(--text)" : "var(--text-mute)",
              fontWeight: active ? 600 : 500,
              letterSpacing: "0.02em",
              boxShadow: active ? "var(--shadow-sm)" : "none",
            }}
          >
            {o}
          </button>
        );
      })}
    </div>
  );
}
