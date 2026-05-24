import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import type { TenantChainRow } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const diff = (Date.now() - then) / 1000;
  if (diff < 60) return "방금";
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`;
  return `${Math.floor(diff / 86400)}일 전`;
}

export function ChainStatusTable({ rows }: { rows: TenantChainRow[] }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const intactCount = rows.filter((r) => r.status === "INTACT").length;
  const tamperedCount = rows.length - intactCount;

  const verifyOne = useMutation({
    mutationFn: (tenantId: string) =>
      apiGet<unknown>(`/api/v1/admin/tenants/${tenantId}/audit-logs/verify`),
    onSuccess: (_data, tenantId) => {
      qc.invalidateQueries({ queryKey: ["platform", "audit-chain", "status"] });
      toast({ variant: "success", title: "tenant 검증 완료", description: tenantId });
    },
    onError: (err: { code?: string; message?: string }) => {
      toast({
        variant: "destructive",
        title: err.code ?? "검증 실패",
        description: err.message ?? "",
      });
    },
  });

  return (
    <div
      className="rounded-lg border"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div
        className="flex items-center justify-between border-b px-4 py-3"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <div className="text-[13px] font-semibold">Tenant별 Chain 상태</div>
        <div className="flex items-center gap-3 text-[11px]">
          <span style={{ color: "var(--success)" }}>● INTACT {intactCount}</span>
          <span style={{ color: "var(--danger)" }}>● TAMPERED {tamperedCount}</span>
        </div>
      </div>
      <table className="w-full text-[13px]">
        <thead>
          <tr
            className="border-b text-[11px] uppercase text-text-mute"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <th className="px-4 py-2 text-left font-semibold">TENANT</th>
            <th className="px-4 py-2 text-left font-semibold">STATUS</th>
            <th className="px-4 py-2 text-right font-semibold">VERIFIED ROWS</th>
            <th className="px-4 py-2 text-left font-semibold">마지막 검증</th>
            <th className="px-4 py-2 text-right font-semibold">액션</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.tenantId}
              className="border-b last:border-b-0"
              style={{ borderColor: "var(--border-subtle)" }}
            >
              <td className="px-4 py-2">{r.name}</td>
              <td className="px-4 py-2">
                <span
                  className="rounded-pill px-2 py-0.5 text-[11px] font-semibold"
                  style={{
                    background:
                      r.status === "INTACT" ? "var(--success-soft)" : "var(--danger-soft)",
                    color: r.status === "INTACT" ? "var(--success)" : "var(--danger)",
                  }}
                >
                  ●{" "}
                  {r.status === "INTACT" ? "INTACT" : `TAMPERED · ${r.tamperedRowCount}`}
                </span>
              </td>
              <td className="px-4 py-2 text-right tabular-nums">
                {nf.format(r.verifiedRows)}
              </td>
              <td className="px-4 py-2 text-text-mute">{relativeTime(r.lastVerifiedAt)}</td>
              <td className="px-4 py-2 text-right">
                <button
                  type="button"
                  onClick={() => navigate(`/tenants/${r.tenantId}/audit-logs`)}
                  className="mr-1 rounded-md border px-2 py-1 text-[11px]"
                  style={{ borderColor: "var(--border)" }}
                >
                  열기
                </button>
                <button
                  type="button"
                  disabled={verifyOne.isPending}
                  onClick={() => verifyOne.mutate(r.tenantId)}
                  className="rounded-md border px-2 py-1 text-[11px] disabled:opacity-50"
                  style={{ borderColor: "var(--border)" }}
                >
                  검증
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
