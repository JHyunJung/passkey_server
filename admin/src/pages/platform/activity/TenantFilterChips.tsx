import type { TopTenantRow } from "@/types/api";

export function TenantFilterChips({
  options,
  selected,
  onToggle,
  onClear,
}: {
  options: TopTenantRow[];
  selected: string[];
  onToggle: (tenantId: string) => void;
  onClear: () => void;
}) {
  if (options.length === 0) return null;
  return (
    <div
      className="rounded-lg border p-4"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div className="mb-2 flex items-center justify-between">
        <div className="text-[13px] font-semibold">Tenant 필터</div>
        {selected.length > 0 && (
          <button
            type="button"
            onClick={onClear}
            className="text-[11px] text-text-mute underline"
          >
            전체 tenant
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onClear}
          className="rounded-pill px-2.5 py-1 text-[11px] font-medium"
          style={{
            background: selected.length === 0 ? "var(--brand-soft)" : "var(--surface-3)",
            color: selected.length === 0 ? "var(--brand)" : "var(--text-mute)",
          }}
        >
          전체 tenant
        </button>
        {options.map((t) => {
          const active = selected.includes(t.tenantId);
          return (
            <button
              key={t.tenantId}
              type="button"
              onClick={() => onToggle(t.tenantId)}
              className="rounded-pill px-2.5 py-1 text-[11px] font-medium"
              style={{
                background: active ? "var(--brand-soft)" : "var(--surface-3)",
                color: active ? "var(--brand)" : "var(--text-mute)",
              }}
            >
              {t.name}
            </button>
          );
        })}
      </div>
    </div>
  );
}
