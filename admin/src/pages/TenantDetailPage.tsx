import { NavLink, Outlet, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { TenantView } from "@/types/api";

const TABS = [
  { to: "overview", label: "개요" },
  { to: "webauthn-config", label: "WebAuthn" },
  { to: "attestation-policy", label: "AAGUID 정책" },
  { to: "api-keys", label: "API Keys" },
  { to: "credentials", label: "Credentials" },
  { to: "audit-logs", label: "Audit Logs" },
  { to: "funnel", label: "Funnel" },
];

export function TenantDetailPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { data, isLoading } = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiGet<TenantView>(`/api/v1/admin/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const initial = (data?.name ?? "?").slice(0, 1).toUpperCase();

  return (
    <div className="space-y-5">
      {/* TenantHeader — mirrors handoff pages-2.jsx TenantHeader */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <div
            className="grid h-11 w-11 shrink-0 place-items-center rounded-lg text-[20px] font-bold text-white"
            style={{
              background:
                "linear-gradient(135deg, var(--accent), var(--accent-hover))",
              letterSpacing: "-0.02em",
            }}
          >
            {initial}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1
                className="text-[22px] font-semibold tracking-tight"
                style={{ color: "var(--text)" }}
              >
                {isLoading ? "불러오는 중…" : (data?.name ?? "Tenant")}
              </h1>
              {data && (
                <Badge
                  variant={data.status === "ACTIVE" ? "success" : "destructive"}
                  className="gap-1"
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: "currentColor" }}
                  />
                  {data.status}
                </Badge>
              )}
            </div>
            {data && (
              <div
                className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                <span className="font-mono">{data.id}</span>
                <span style={{ color: "var(--text-faint)" }}>·</span>
                <span className="font-mono">slug: {data.slug}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tab bar — tokens.css .tabs */}
      <nav
        className="-mx-1 flex gap-1 overflow-x-auto"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
      >
        {TABS.map((t) => (
          <NavLink
            key={t.to}
            to={t.to}
            className={({ isActive }) =>
              cn(
                "whitespace-nowrap px-3.5 py-2.5 text-[13px] font-medium transition-colors",
                "-mb-px border-b-2",
                isActive
                  ? "font-semibold"
                  : "text-text-soft hover:text-text",
              )
            }
            style={({ isActive }) => ({
              borderBottomColor: isActive ? "var(--accent)" : "transparent",
              color: isActive ? "var(--accent)" : undefined,
            })}
          >
            {t.label}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </div>
  );
}
