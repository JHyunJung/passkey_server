import { Link, useLocation, useMatch } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { apiGet } from "@/lib/api";
import type { TenantView } from "@/types/api";

const LABELS: Record<string, string> = {
  tenants: "Tenants",
  admins: "운영자",
  system: "시스템",
  overview: "개요",
  "webauthn-config": "WebAuthn",
  "attestation-policy": "AAGUID 정책",
  "api-keys": "API Keys",
  credentials: "Credentials",
  "audit-logs": "Audit Log",
  funnel: "Funnel",
};

export function Breadcrumb() {
  const location = useLocation();
  const tenantMatch = useMatch("/tenants/:tenantId/*");
  const tenantId = tenantMatch?.params.tenantId;

  // Resolve the tenant segment to a human name when in scope. Re-uses the
  // tenant detail query key so this share's the Sidebar / OverviewTab cache.
  const { data: tenant } = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiGet<TenantView>(`/api/v1/admin/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const parts = location.pathname.split("/").filter(Boolean);
  if (parts.length === 0) return null;

  const crumbs: { label: string; to: string; mono?: boolean }[] = [];
  let acc = "";
  for (let i = 0; i < parts.length; i++) {
    acc += `/${parts[i]}`;
    const raw = parts[i]!;
    let label: string;
    let mono = false;
    if (raw === tenantId) {
      label = tenant?.name ?? raw.slice(0, 8);
      mono = !tenant?.name;
    } else {
      label = LABELS[raw] ?? raw;
    }
    crumbs.push({ label, to: acc, mono });
  }

  return (
    <nav
      aria-label="breadcrumb"
      className="flex min-w-0 items-center gap-1.5 text-[13px]"
      style={{ color: "var(--text-soft)" }}
    >
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        const color = last ? "var(--text)" : "var(--text-mute)";
        const weight = last ? 600 : 500;
        return (
          <span key={c.to} className="flex items-center gap-1.5">
            {i > 0 && (
              <ChevronRight className="h-3 w-3" style={{ color: "var(--text-faint)" }} />
            )}
            {last ? (
              <span
                className={c.mono ? "font-mono" : undefined}
                style={{ color, fontWeight: weight }}
              >
                {c.label}
              </span>
            ) : (
              <Link
                to={c.to}
                className={c.mono ? "font-mono hover:opacity-90" : "hover:opacity-90"}
                style={{ color, fontWeight: weight }}
              >
                {c.label}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
