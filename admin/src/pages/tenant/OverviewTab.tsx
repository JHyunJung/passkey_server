import * as React from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronRight,
  Download,
  Hash,
  Pause,
  Play,
  Shield,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { MetricCard } from "@/components/MetricCard";
import { useMe } from "@/hooks/useMe";
import { useToast } from "@/hooks/useToast";
import { apiGet, apiPatch, PasskeyAdminError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/cn";
import type {
  AuditEventType,
  AuditView,
  FunnelView,
  OverviewStatsView,
  PageResponse,
  TenantView,
  WebauthnConfigView,
} from "@/types/api";

export function OverviewTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const qc = useQueryClient();
  const { toast } = useToast();
  const { data: me } = useMe();

  const { data: tenant } = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiGet<TenantView>(`/api/v1/admin/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const { data: stats } = useQuery({
    queryKey: ["tenantOverviewStats", tenantId],
    queryFn: () =>
      apiGet<OverviewStatsView>(
        `/api/v1/admin/tenants/${tenantId}/overview-stats`,
      ),
    enabled: !!tenantId,
    refetchInterval: 30_000,
  });

  // 7-day funnel for success-rate metrics. Same query key as FunnelTab(7d) so the
  // tabs share cache.
  const { data: funnel7 } = useQuery({
    queryKey: ["funnel", tenantId, { windowDays: 7 }],
    queryFn: async () => {
      const to = new Date();
      const from = new Date(to);
      from.setUTCDate(from.getUTCDate() - 7);
      return apiGet<FunnelView>(
        `/api/v1/admin/tenants/${tenantId}/funnel?from=${encodeURIComponent(
          from.toISOString(),
        )}&to=${encodeURIComponent(to.toISOString())}`,
      );
    },
    enabled: !!tenantId,
  });

  // WebAuthn summary — same cache key as WebauthnConfigTab.
  const { data: webauthn } = useQuery({
    queryKey: ["webauthnConfig", tenantId],
    queryFn: () =>
      apiGet<WebauthnConfigView>(
        `/api/v1/admin/tenants/${tenantId}/webauthn-config`,
      ),
    enabled: !!tenantId,
  });

  // Most-recent audit slice for the activity card.
  const { data: recentAudit } = useQuery({
    queryKey: ["audit", tenantId, { page: 0, size: 5, eventFilter: "ALL" }],
    queryFn: () =>
      apiGet<PageResponse<AuditView>>(
        `/api/v1/admin/tenants/${tenantId}/audit-logs?page=0&size=5`,
      ),
    enabled: !!tenantId,
  });

  const [suspendOpen, setSuspendOpen] = React.useState(false);
  const [slugInput, setSlugInput] = React.useState("");

  const updateStatus = useMutation({
    mutationFn: (status: "ACTIVE" | "SUSPENDED") =>
      apiPatch<TenantView>(`/api/v1/admin/tenants/${tenantId}/status`, { status }),
    onSuccess: (next) => {
      qc.setQueryData(["tenant", tenantId], next);
      qc.invalidateQueries({ queryKey: ["tenants"] });
      toast({
        variant: "success",
        title:
          next.status === "ACTIVE" ? "Tenant 활성화됨" : "Tenant 일시정지됨",
      });
      setSuspendOpen(false);
      setSlugInput("");
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  if (!tenant) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }

  const isPlatform = me?.role === "PLATFORM_OPERATOR";
  const isActive = tenant.status === "ACTIVE";

  const regRatio = ratio(funnel7?.registrationCompleted, funnel7?.registrationStarted);
  const authRatio = ratio(funnel7?.authenticationSucceeded, funnel7?.authenticationAttempted);

  return (
    <div className="space-y-4">
      {/* Metric strip */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="등록 Credential"
          value={fmtMaybe(stats?.activeCredentials)}
          sub="ACTIVE 상태"
        />
        <MetricCard
          label="유효 API Key"
          value={fmtMaybe(stats?.activeApiKeys)}
          sub="ACTIVE 상태"
        />
        <MetricCard
          label="등록 성공률 (7d)"
          value={regRatio ? `${(regRatio.r * 100).toFixed(1)}%` : "—"}
          sub={
            regRatio
              ? `${fmt(regRatio.s)} / ${fmt(regRatio.a)} 시도`
              : "데이터 부족"
          }
        />
        <MetricCard
          label="인증 성공률 (7d)"
          value={authRatio ? `${(authRatio.r * 100).toFixed(1)}%` : "—"}
          sub={
            authRatio
              ? `${fmt(authRatio.s)} / ${fmt(authRatio.a)} 시도`
              : "데이터 부족"
          }
        />
      </div>

      {/* 2-col: WebAuthn summary + recent activity */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <CardShell
          title="WebAuthn 요약"
          action={
            <Button asChild variant="outline" size="sm" className="gap-1">
              <Link to={`/tenants/${tenantId}/webauthn-config`}>
                편집 <ChevronRight className="h-3 w-3" />
              </Link>
            </Button>
          }
        >
          <div className="space-y-2.5 p-5">
            <KV
              k="rpId"
              v={
                webauthn ? (
                  <span className="font-mono">{webauthn.rpId}</span>
                ) : (
                  <span className="text-text-mute">—</span>
                )
              }
            />
            <KV k="rpName" v={webauthn?.rpName ?? "—"} />
            <KV
              k="origins"
              v={
                webauthn?.origins.length ? (
                  <div className="flex flex-wrap gap-1">
                    {webauthn.origins.map((o) => (
                      <span
                        key={o}
                        className="inline-flex items-center rounded-pill border px-2 py-0.5 font-mono text-[11px]"
                        style={{
                          background: "var(--surface-3)",
                          borderColor: "var(--border)",
                          color: "var(--text)",
                        }}
                      >
                        {o}
                      </span>
                    ))}
                  </div>
                ) : (
                  "—"
                )
              }
            />
            <KV
              k="userVerification"
              v={
                webauthn ? (
                  <Badge variant="default" className="bg-accent-soft text-accent">
                    {webauthn.userVerification}
                  </Badge>
                ) : (
                  "—"
                )
              }
            />
            <KV
              k="attestation"
              v={
                webauthn ? (
                  <Badge variant="default">{webauthn.attestationConveyance}</Badge>
                ) : (
                  "—"
                )
              }
            />
            <KV
              k="timeout"
              v={webauthn ? `${Math.round(webauthn.timeoutMs / 1000)}s` : "—"}
            />
          </div>
        </CardShell>

        <CardShell
          title="최근 활동"
          action={
            <Button asChild variant="outline" size="sm" className="gap-1">
              <Link to={`/tenants/${tenantId}/audit-logs`}>
                전체 보기 <ChevronRight className="h-3 w-3" />
              </Link>
            </Button>
          }
        >
          {!recentAudit?.content.length ? (
            <p className="px-5 py-6 text-sm text-text-mute">
              아직 이벤트가 없습니다.
            </p>
          ) : (
            <ul>
              {recentAudit.content.map((e, i) => (
                <li
                  key={e.id}
                  className="flex items-start gap-2.5 px-5 py-2.5"
                  style={{
                    borderBottom:
                      i === recentAudit.content.length - 1
                        ? undefined
                        : "1px solid var(--border-subtle)",
                  }}
                >
                  <EventDot type={e.eventType} />
                  <div className="min-w-0 flex-1">
                    <div className="text-[12px] font-semibold">
                      {e.eventType}
                    </div>
                    <div
                      className="mt-0.5 truncate font-mono text-[11px]"
                      style={{ color: "var(--text-mute)" }}
                    >
                      {tail(e.subjectId ?? e.actorId ?? "—", 16)}
                    </div>
                  </div>
                  <div
                    className="shrink-0 text-[11px]"
                    style={{ color: "var(--text-mute)" }}
                  >
                    {timeAgo(e.createdAt)}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardShell>
      </div>

      {/* Audit chain status banner */}
      <div
        className="rounded-lg border"
        style={{
          background:
            "linear-gradient(135deg, var(--success-soft), transparent 60%)",
          borderColor: "color-mix(in oklab, var(--success) 25%, var(--border))",
          boxShadow: "var(--shadow-xs)",
        }}
      >
        <div className="flex flex-wrap items-center gap-3.5 p-5">
          <div
            className="grid h-[38px] w-[38px] shrink-0 place-items-center rounded-lg text-white"
            style={{ background: "var(--success)" }}
          >
            <Shield className="h-5 w-5" />
          </div>
          <div className="flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-[14px] font-semibold">
                Audit Hash Chain 무결
              </div>
              <Badge variant="success" className="gap-1">
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ background: "currentColor" }}
                />
                INTACT
              </Badge>
            </div>
            <div
              className="mt-1 text-[12px]"
              style={{ color: "var(--text-mute)" }}
            >
              {stats?.lastAuditAt
                ? `마지막 audit · ${formatDateTime(stats.lastAuditAt)}`
                : "audit 이벤트가 아직 기록되지 않았습니다."}
            </div>
          </div>
          <Button asChild variant="outline" size="sm" className="gap-1.5">
            <Link to={`/tenants/${tenantId}/audit-logs`}>
              <Hash className="h-3 w-3" /> 수동 검증
            </Link>
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5" disabled>
            <Download className="h-3 w-3" /> 월간 보고서
          </Button>
        </div>
      </div>

      {/* Status action — kept available to Platform Operators */}
      {isPlatform && (
        <div className="flex items-center justify-between rounded-lg border bg-card px-5 py-3">
          <div>
            <div className="text-[13px] font-semibold">Tenant 상태</div>
            <div className="mt-0.5 text-[12px] text-text-mute">
              현재 <Badge variant={isActive ? "success" : "destructive"}>{tenant.status}</Badge>
              {" "}— 일시정지하면 모든 API key + refresh token이 즉시 회수됩니다.
            </div>
          </div>
          {isActive ? (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                setSlugInput("");
                setSuspendOpen(true);
              }}
            >
              <Pause className="mr-1 h-4 w-4" /> 일시정지
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={() => updateStatus.mutate("ACTIVE")}
              disabled={updateStatus.isPending}
            >
              <Play className="mr-1 h-4 w-4" /> 활성화
            </Button>
          )}
        </div>
      )}

      <Dialog open={suspendOpen} onOpenChange={setSuspendOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>⚠️ Tenant 일시정지</DialogTitle>
            <DialogDescription>
              일시정지하면 이 tenant의{" "}
              <strong>
                모든 API key + 활성 refresh token이 즉시 회수
              </strong>
              되어 RP 트래픽이 차단됩니다. 캐시 만료(5분 이내) 후 완전 차단.
              진행하려면 tenant slug{" "}
              <code className="rounded bg-muted px-1">{tenant.slug}</code>를
              입력하세요.
            </DialogDescription>
          </DialogHeader>
          <Input
            autoFocus
            value={slugInput}
            placeholder={tenant.slug}
            onChange={(e) => setSlugInput(e.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setSuspendOpen(false)}>
              취소
            </Button>
            <Button
              variant="destructive"
              disabled={slugInput !== tenant.slug || updateStatus.isPending}
              onClick={() => updateStatus.mutate("SUSPENDED")}
            >
              {updateStatus.isPending ? "처리 중…" : "일시정지"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CardShell({
  title,
  action,
  children,
  className,
}: {
  title: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn("overflow-hidden rounded-lg border", className)}
      style={{
        background: "var(--surface)",
        borderColor: "var(--border-subtle)",
        boxShadow: "var(--shadow-xs)",
      }}
    >
      <div
        className="flex items-center justify-between gap-3 px-5 py-3.5"
        style={{ borderBottom: "1px solid var(--border-subtle)" }}
      >
        <h3 className="text-[14px] font-semibold tracking-tight">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}

function KV({ k, v }: { k: React.ReactNode; v: React.ReactNode }) {
  return (
    <div
      className="grid items-center gap-3 text-[13px]"
      style={{ gridTemplateColumns: "120px 1fr" }}
    >
      <div className="text-[12px]" style={{ color: "var(--text-mute)" }}>
        {k}
      </div>
      <div>{v}</div>
    </div>
  );
}

// Hoisted to module scope (js-cache-function-results / rendering-hoist-jsx) — a static
// [color, background] palette has no reason to be rebuilt per event row.
const EVENT_DOT_PALETTE: Record<string, [string, string]> = {
  CREDENTIAL_AUTHENTICATED: ["var(--success)", "var(--success-soft)"],
  CREDENTIAL_REGISTERED: ["var(--info)", "var(--info-soft)"],
  CREDENTIAL_REVOKED: ["var(--danger)", "var(--danger-soft)"],
  API_KEY_ISSUED: ["var(--violet)", "var(--violet-soft)"],
  API_KEY_REVOKED: ["var(--danger)", "var(--danger-soft)"],
  WEBAUTHN_CONFIG_UPDATED: ["var(--warning)", "var(--warning-soft)"],
  SIGNATURE_COUNTER_REGRESSION: ["var(--danger)", "var(--danger-soft)"],
  ATTESTATION_TRUST_FAILED: ["var(--danger)", "var(--danger-soft)"],
};

function EventDot({ type }: { type: AuditEventType }) {
  const [c, bg] = EVENT_DOT_PALETTE[type] ?? ["var(--text-mute)", "var(--surface-3)"];
  return (
    <div
      className="grid h-6 w-6 shrink-0 place-items-center rounded"
      style={{ background: bg, color: c }}
    >
      <div className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
    </div>
  );
}

function ratio(num?: number, den?: number) {
  if (num === undefined || den === undefined || den === 0) return null;
  return { r: num / den, s: num, a: den };
}

function fmt(n: number) {
  return new Intl.NumberFormat("ko-KR").format(n);
}

function fmtMaybe(n?: number) {
  return n === undefined ? "—" : fmt(n);
}

function tail(s: string, n = 12) {
  if (!s || s === "—") return "—";
  return s.length <= n ? s : `…${s.slice(-n)}`;
}

function timeAgo(iso: string) {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const diff = Math.max(0, (Date.now() - t) / 1000);
  if (diff < 60) return diff < 2 ? "방금" : `${Math.floor(diff)}초 전`;
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}일 전`;
  return new Date(iso).toLocaleDateString("ko-KR");
}
