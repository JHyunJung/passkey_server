import { Download } from "lucide-react";
import {
  useAuditChainStatus,
  useVerifyAllChain,
} from "@/hooks/usePlatformAuditChain";
import { ChainMetricsRow } from "@/pages/platform/audit-chain/ChainMetricsRow";
import { TamperedAlertBanner } from "@/pages/platform/audit-chain/TamperedAlertBanner";
import { ChainStatusTable } from "@/pages/platform/audit-chain/ChainStatusTable";
import { downloadCsv, rowsToCsv } from "@/lib/csv";
import { useToast } from "@/hooks/useToast";

export function AuditChainMonitorPage() {
  const status = useAuditChainStatus();
  const verifyAll = useVerifyAllChain();
  const { toast } = useToast();

  function handleReport() {
    if (!status.data) return;
    const csv = rowsToCsv(status.data.perTenant, [
      { key: "name", header: "tenant" },
      { key: "slug", header: "slug" },
      { key: "tenantId", header: "tenantId" },
      { key: "status", header: "status" },
      { key: "verifiedRows", header: "verifiedRows" },
      { key: "tamperedRowCount", header: "tamperedRowCount" },
      { key: "lastVerifiedAt", header: "lastVerifiedAt" },
    ]);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadCsv(`audit-chain-report-${stamp}.csv`, csv);
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[22px] font-semibold">Audit Chain Monitor</h1>
          <p className="text-[13px] text-text-mute">
            전체 tenant의 SHA-256 hash chain 무결성 상태.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={!status.data}
            onClick={handleReport}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12px] font-medium disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            <Download className="h-3.5 w-3.5" /> 보고서 (CSV)
          </button>
          <button
            type="button"
            disabled={verifyAll.isPending}
            onClick={() =>
              verifyAll.mutate(undefined, {
                onSuccess: (data) =>
                  toast({
                    variant: data.tenantsTampered === 0 ? "success" : "destructive",
                    title: `${data.tenantsChecked}개 tenant 검증 완료`,
                    description: `INTACT ${data.tenantsIntact} · TAMPERED ${data.tenantsTampered}${
                      data.errors.length ? ` · 오류 ${data.errors.length}건` : ""
                    }`,
                  }),
                onError: (err: { code?: string; message?: string }) =>
                  toast({
                    variant: "destructive",
                    title: err.code ?? "검증 실패",
                    description: err.message ?? "",
                  }),
              })
            }
            className="rounded-md px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-50"
            style={{ background: "var(--brand)" }}
          >
            {verifyAll.isPending ? "검증 중…" : "# 전체 즉시 검증"}
          </button>
        </div>
      </div>
      <ChainMetricsRow status={status.data} />
      <TamperedAlertBanner tampered={status.data?.tamperedTenants ?? []} />
      {status.data && <ChainStatusTable rows={status.data.perTenant} />}
    </div>
  );
}
