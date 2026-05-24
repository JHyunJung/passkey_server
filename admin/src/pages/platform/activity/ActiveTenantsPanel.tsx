import type { TopTenantRow } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

export function ActiveTenantsPanel({ rows }: { rows: TopTenantRow[] }) {
  if (!rows.length) {
    return (
      <div
        className="rounded-lg border p-4 text-sm text-text-mute"
        style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
      >
        활발한 tenant가 없습니다.
      </div>
    );
  }
  return (
    <div
      className="rounded-lg border"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div
        className="border-b px-4 py-3 text-[13px] font-semibold"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        활발한 Tenant
      </div>
      <ul>
        {rows.map((t) => (
          <li
            key={t.tenantId}
            className="flex items-center justify-between border-b px-4 py-2 last:border-b-0"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <div className="flex items-center gap-2">
              <div
                className="flex h-7 w-7 items-center justify-center rounded text-[11px] font-semibold"
                style={{ background: "var(--surface-3)", color: "var(--text)" }}
              >
                {t.name.charAt(0).toUpperCase()}
              </div>
              <div>
                <div className="text-[13px] font-medium">{t.name}</div>
                <div className="text-[11px] text-text-mute">
                  {nf.format(t.activeCredentials)} credentials
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-[13px] tabular-nums">{nf.format(t.eventCount24h)}</div>
              <div className="text-[11px] text-text-mute">24h events</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
