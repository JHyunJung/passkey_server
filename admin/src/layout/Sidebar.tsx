import { NavLink, useMatch, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  BarChart3,
  Building2,
  ChevronLeft,
  Cog,
  FileText,
  Fingerprint,
  Globe,
  Hash,
  KeyRound,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { BrandMark } from "@/components/BrandMark";
import { useAuditChainStatus } from "@/hooks/usePlatformAuditChain";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { Me, TenantView } from "@/types/api";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  external?: boolean; // hash-routed console mock target
  mock?: boolean; // show "mock" pill
}

// Platform-scope nav (flat, mirrors the handoff design).
const NAV_PLATFORM: NavItem[] = [
  { to: "/tenants", label: "Tenants", icon: Building2 },
  { to: "/platform/activity", label: "Activity", icon: Activity },
  { to: "/platform/audit-chain", label: "Audit Chain", icon: Hash },
  { to: "/admins", label: "설정", icon: Cog },
];

const tenantTabs = (tenantId: string): NavItem[] => [
  { to: `/tenants/${tenantId}/overview`, label: "개요", icon: Activity },
  { to: `/tenants/${tenantId}/webauthn-config`, label: "WebAuthn", icon: Globe },
  { to: `/tenants/${tenantId}/attestation-policy`, label: "AAGUID 정책", icon: ShieldCheck },
  { to: `/tenants/${tenantId}/api-keys`, label: "API Keys", icon: KeyRound },
  { to: `/tenants/${tenantId}/credentials`, label: "Credentials", icon: Fingerprint },
  { to: `/tenants/${tenantId}/audit-logs`, label: "Audit Logs", icon: FileText },
  { to: `/tenants/${tenantId}/funnel`, label: "Funnel", icon: BarChart3 },
];

export function Sidebar({ me }: { me: Me }) {
  const isPlatform = me.role === "PLATFORM_OPERATOR";
  const match = useMatch("/tenants/:tenantId/*");
  const tenantId = match?.params.tenantId;
  const params = useParams();
  const activeTenantId = tenantId ?? params.tenantId;

  // Pull the tenant header only when a tenant is in scope. Reuses the same cache key as
  // OverviewTab/CredentialsTab so the panel and the page header agree on the tenant name.
  const { data: tenant } = useQuery({
    queryKey: ["tenant", activeTenantId],
    queryFn: () => apiGet<TenantView>(`/api/v1/admin/tenants/${activeTenantId}`),
    enabled: !!activeTenantId,
  });

  // Live audit chain status — drives the footer pill. PLATFORM_OPERATOR only; RP_ADMIN
  // users get a static fallback to avoid noisy 403s. Shares the cache key with
  // AuditChainMonitorPage so the data fetch happens at most once per minute.
  const { data: chainStatus } = useAuditChainStatus({ enabled: isPlatform });

  return (
    <aside
      className="sticky top-0 hidden h-screen w-[232px] shrink-0 flex-col overflow-hidden border-r border-border bg-surface md:flex"
      style={{ borderRightColor: "var(--border)" }}
    >
      {/* Brand */}
      <div className="flex items-center gap-2.5 border-b border-border px-4 py-4">
        <BrandMark size={26} />
        <div className="min-w-0">
          <p className="text-[13px] font-semibold leading-tight tracking-tight text-text">
            Passkey Admin
          </p>
          <p className="text-[11px] leading-tight text-text-mute">Crosscert · prod</p>
        </div>
      </div>

      {/* Tenant context block — only when inside /tenants/:id/* */}
      {activeTenantId && (
        <div className="border-b border-border px-3 py-3">
          {isPlatform && (
            <NavLink
              to="/tenants"
              className="mb-1.5 inline-flex items-center gap-1 rounded px-1 py-0.5 text-[11px] text-text-mute hover:bg-surface-3 hover:text-text"
            >
              <ChevronLeft className="h-3 w-3" /> Tenants
            </NavLink>
          )}
          <div className="flex items-center gap-2">
            <div className="grid h-6 w-6 place-items-center rounded text-[11px] font-bold"
              style={{ background: "var(--accent-soft)", color: "var(--accent)" }}>
              {(tenant?.name ?? "?").slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="truncate text-[13px] font-semibold leading-tight tracking-tight">
                {tenant?.name ?? "…"}
              </div>
              <div className="truncate font-mono text-[11px] leading-tight text-text-mute">
                {tenant?.slug ?? activeTenantId.slice(0, 8)}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Nav — flat, matches handoff shell.jsx */}
      <nav className="flex flex-1 flex-col gap-0.5 overflow-auto p-2">
        {activeTenantId ? (
          tenantTabs(activeTenantId).map((item) => <NavBtn key={item.to} item={item} />)
        ) : (
          <>
            {isPlatform &&
              NAV_PLATFORM.map((item) => <NavBtn key={item.to} item={item} />)}
            {!isPlatform &&
              me.tenantId &&
              tenantTabs(me.tenantId).map((item) => <NavBtn key={item.to} item={item} />)}
          </>
        )}
      </nav>

      {/* Footer · Audit chain status pill (live for PLATFORM, static for RP_ADMIN) */}
      <div className="border-t border-border px-3 py-3">
        {isPlatform ? (
          (() => {
            const intact =
              !!chainStatus &&
              chainStatus.intactTenants === chainStatus.totalTenants;
            const color = chainStatus
              ? intact
                ? "var(--success)"
                : "var(--danger)"
              : "var(--text-mute)";
            const bg = chainStatus
              ? intact
                ? "var(--success-soft)"
                : "var(--danger-soft)"
              : "var(--surface-3)";
            const label = chainStatus
              ? intact
                ? "AUDIT CHAIN OK"
                : "AUDIT CHAIN ALERT"
              : "AUDIT CHAIN …";
            const sub = chainStatus
              ? `${chainStatus.totalVerifiedRows.toLocaleString("ko-KR")}행 · ${chainStatus.schedulerCron}`
              : "상태 조회 중";
            return (
              <div
                className="space-y-1 rounded-md border px-2.5 py-2"
                style={{
                  background: bg,
                  borderColor: `color-mix(in oklab, ${color} 20%, transparent)`,
                }}
              >
                <div
                  className="flex items-center gap-1.5 text-[11px] font-semibold"
                  style={{ color }}
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{
                      background: color,
                      boxShadow: `0 0 0 3px color-mix(in oklab, ${color} 25%, transparent)`,
                    }}
                  />
                  {label}
                </div>
                <div className="text-[11px] text-text-mute">{sub}</div>
              </div>
            );
          })()
        ) : (
          <div
            className="space-y-1 rounded-md border px-2.5 py-2"
            style={{
              background: "var(--success-soft)",
              borderColor: "color-mix(in oklab, var(--success) 20%, transparent)",
            }}
          >
            <div
              className="flex items-center gap-1.5 text-[11px] font-semibold"
              style={{ color: "var(--success)" }}
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  background: "var(--success)",
                  boxShadow:
                    "0 0 0 3px color-mix(in oklab, var(--success) 25%, transparent)",
                }}
              />
              AUDIT CHAIN OK
            </div>
            <div className="text-[11px] text-text-mute">로컬 검증 · 활성</div>
          </div>
        )}
      </div>
    </aside>
  );
}

function NavBtn({ item }: { item: NavItem }) {
  const Icon = item.icon;
  const baseClass =
    "group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors duration-fast ease-out";
  const inactive = "font-medium text-text-soft hover:bg-surface-3 hover:text-text";

  // External (hash-routed mock) entries use a plain anchor so they reach
  // /console with the hash intact.
  if (item.external) {
    return (
      <a
        href={item.to}
        className={cn(baseClass, inactive)}
        title="디자인 mock — 운영 데이터 아님"
      >
        <Icon className="h-4 w-4" />
        <span className="flex-1">{item.label}</span>
        {item.mock && (
          <span
            className="rounded-pill px-1.5 text-[10px] font-semibold uppercase tracking-wider"
            style={{ background: "var(--surface-3)", color: "var(--text-faint)" }}
          >
            mock
          </span>
        )}
      </a>
    );
  }

  return (
    <NavLink
      to={item.to}
      end={item.end}
      className={({ isActive }) =>
        cn(baseClass, isActive ? "font-semibold" : inactive)
      }
      style={({ isActive }) =>
        isActive
          ? { background: "var(--accent-soft)", color: "var(--accent)" }
          : undefined
      }
    >
      <Icon className="h-4 w-4" />
      <span>{item.label}</span>
    </NavLink>
  );
}
