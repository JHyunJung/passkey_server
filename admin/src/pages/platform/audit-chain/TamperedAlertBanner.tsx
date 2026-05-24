import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import type { TamperedTenantSummary } from "@/types/api";
import { useToast } from "@/hooks/useToast";

export function TamperedAlertBanner({
  tampered,
}: {
  tampered: TamperedTenantSummary[];
}) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const first = tampered[0];
  if (!first) return null;
  const heading =
    tampered.length === 1
      ? `${first.name} tenant에서 ${first.tamperedRowCount}개 audit row의 hash가 일치하지 않습니다. DBA + 보안팀 알림 필요.`
      : `${tampered.length}개 tenant에서 위변조 의심 — 자세히 보기`;
  return (
    <div
      className="flex items-center gap-3 rounded-md border p-4"
      style={{
        background: "var(--danger-soft)",
        borderColor: "color-mix(in oklab, var(--danger) 25%, transparent)",
      }}
    >
      <div
        className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
        style={{ background: "var(--danger)" }}
      >
        <AlertTriangle className="h-5 w-5 text-white" />
      </div>
      <div className="flex-1">
        <div
          className="text-[13px] font-semibold"
          style={{ color: "var(--danger)" }}
        >
          위변조 의심 — 즉시 조사 필요
        </div>
        <div className="mt-0.5 text-[12px]" style={{ color: "var(--text)" }}>
          {heading}
        </div>
      </div>
      <button
        type="button"
        onClick={() => navigate(`/tenants/${first.tenantId}/audit-logs`)}
        className="rounded-md border px-3 py-1.5 text-[12px] font-medium"
        style={{ borderColor: "var(--border)", color: "var(--text)" }}
      >
        tenant 열기 →
      </button>
      <button
        type="button"
        onClick={() =>
          toast({
            variant: "default",
            title: "Incident 시스템 연동 예정",
            description: "외부 ticket 시스템 통합은 별도 spec으로 진행합니다.",
          })
        }
        className="rounded-md px-3 py-1.5 text-[12px] font-semibold text-white"
        style={{ background: "var(--danger)" }}
      >
        ⚠ Incident 생성
      </button>
    </div>
  );
}
