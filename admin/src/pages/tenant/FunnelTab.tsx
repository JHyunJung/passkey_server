import * as React from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BarChart3, Info } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { FunnelView } from "@/types/api";

type Window = 1 | 7 | 30;
const WINDOWS: Array<{ v: Window; label: string }> = [
  { v: 1, label: "24h" },
  { v: 7, label: "7d" },
  { v: 30, label: "30d" },
];

export function FunnelTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const [windowDays, setWindowDays] = React.useState<Window>(7);

  const { data, isLoading } = useQuery({
    queryKey: ["funnel", tenantId, { windowDays }],
    queryFn: async () => {
      const to = new Date();
      const from = new Date(to);
      from.setUTCDate(from.getUTCDate() - windowDays);
      return apiGet<FunnelView>(
        `/api/v1/admin/tenants/${tenantId}/funnel?from=${encodeURIComponent(
          from.toISOString(),
        )}&to=${encodeURIComponent(to.toISOString())}`,
      );
    },
    enabled: !!tenantId,
  });

  return (
    <div className="space-y-4">
      <PageHeader
        title="Funnel"
        description="Tenant의 등록 / 인증 ceremony 흐름 통계."
      />

      {/* Conversion funnel card */}
      <div
        className="overflow-hidden rounded-lg border"
        style={{
          background: "var(--surface)",
          borderColor: "var(--border-subtle)",
          boxShadow: "var(--shadow-xs)",
        }}
      >
        <div
          className="flex flex-wrap items-start justify-between gap-3 px-5 py-3.5"
          style={{ borderBottom: "1px solid var(--border-subtle)" }}
        >
          <div className="min-w-0">
            <h3 className="text-[14px] font-semibold tracking-tight">
              Conversion Funnel
            </h3>
            <p
              className="mt-0.5 text-[12px]"
              style={{ color: "var(--text-mute)" }}
            >
              ceremony 단계별 시도/성공 비율. 최근 {windowDays}일.
            </p>
          </div>
          <div className="flex gap-1">
            {WINDOWS.map((w) => {
              const active = windowDays === w.v;
              return (
                <Button
                  key={w.v}
                  size="sm"
                  variant={active ? "default" : "outline"}
                  onClick={() => setWindowDays(w.v)}
                  className={cn("h-8 px-3 text-[12px]")}
                  style={
                    active
                      ? {
                          background: "var(--accent-soft)",
                          borderColor: "var(--accent)",
                          color: "var(--accent)",
                        }
                      : undefined
                  }
                >
                  {w.label}
                </Button>
              );
            })}
          </div>
        </div>
        <div className="p-5">
          {isLoading || !data ? (
            <p className="text-sm text-muted-foreground">불러오는 중…</p>
          ) : (
            <Funnel f={data} />
          )}
        </div>
      </div>

      {/* Side panels — visual placeholders for series data the backend doesn't yet expose */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <PlaceholderCard
          title="일별 인증 시도 vs 성공"
          hint="일별 시계열 endpoint는 아직 연동되지 않았습니다. 현재는 funnel summary만 표시됩니다."
        />
        <PlaceholderCard
          title="이벤트 타입별 분포"
          hint="audit log를 그룹화해 보여주는 분포는 audit-logs 탭에서 필터로 확인할 수 있습니다."
        />
      </div>
    </div>
  );
}

function Funnel({ f }: { f: FunnelView }) {
  const steps = [
    {
      label: "등록 시도",
      value: f.registrationStarted,
      color: "var(--info)",
    },
    {
      label: "등록 성공",
      value: f.registrationCompleted,
      color: "var(--accent)",
      ratio: ratio(f.registrationCompleted, f.registrationStarted),
    },
    {
      label: "인증 시도",
      value: f.authenticationAttempted,
      color: "var(--violet)",
    },
    {
      label: "인증 성공",
      value: f.authenticationSucceeded,
      color: "var(--success)",
      ratio: ratio(f.authenticationSucceeded, f.authenticationAttempted),
    },
  ];
  const max = Math.max(1, ...steps.map((s) => s.value));

  return (
    <div className="space-y-3">
      {steps.map((s) => (
        <div key={s.label}>
          <div className="mb-1.5 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: s.color }}
              />
              <span className="text-[13px] font-medium">{s.label}</span>
              {typeof s.ratio === "number" && (
                <Badge variant="success" className="text-[10px]">
                  {(s.ratio * 100).toFixed(1)}%
                </Badge>
              )}
            </div>
            <div className="font-mono text-[13px] font-semibold tabular-nums">
              {s.value.toLocaleString()}
            </div>
          </div>
          <div
            className="h-2 overflow-hidden rounded-pill"
            style={{ background: "var(--surface-3)" }}
          >
            <div
              className="h-full rounded-pill"
              style={{
                width: `${(s.value / max) * 100}%`,
                background: s.color,
                transition: "width 600ms var(--ease-out)",
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function ratio(num: number, den: number): number | null {
  if (!den || den === 0) return null;
  return num / den;
}

function PlaceholderCard({
  title,
  hint,
}: {
  title: string;
  hint: string;
}) {
  return (
    <div
      className="overflow-hidden rounded-lg border"
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
      </div>
      <div
        className="flex flex-col items-center gap-3 px-5 py-10 text-center"
        style={{ color: "var(--text-mute)" }}
      >
        <div
          className="grid h-12 w-12 place-items-center rounded-lg"
          style={{ background: "var(--surface-3)" }}
        >
          <BarChart3 className="h-5 w-5" />
        </div>
        <p className="text-[13px] font-semibold" style={{ color: "var(--text)" }}>
          데이터 미연동
        </p>
        <p className="max-w-[320px] text-[12px]">{hint}</p>
        <div
          className="mt-2 flex items-center gap-1.5 text-[11px]"
          style={{ color: "var(--text-faint)" }}
        >
          <Info className="h-3 w-3" />
          backend에 시계열 endpoint가 추가되면 자동으로 표시됩니다.
        </div>
      </div>
    </div>
  );
}
