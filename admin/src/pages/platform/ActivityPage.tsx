import * as React from "react";
import { Download, RefreshCw } from "lucide-react";
import { useActivitySummary, useActivityFeed } from "@/hooks/usePlatformActivity";
import { ActivityMetricsRow } from "@/pages/platform/activity/ActivityMetricsRow";
import {
  ActivityFeedPanel,
  type FeedCategory,
} from "@/pages/platform/activity/ActivityFeedPanel";
import { ActiveTenantsPanel } from "@/pages/platform/activity/ActiveTenantsPanel";
import { TenantFilterChips } from "@/pages/platform/activity/TenantFilterChips";
import { downloadCsv, rowsToCsv } from "@/lib/csv";
import { useToast } from "@/hooks/useToast";

const MAX_EXPORT_ROWS = 5_000;

export function ActivityPage() {
  const [tenantIds, setTenantIds] = React.useState<string[]>([]);
  const [feedCategory, setFeedCategory] = React.useState<FeedCategory>("all");
  const [exporting, setExporting] = React.useState(false);
  const summary = useActivitySummary();
  const { toast } = useToast();
  // Export feed shares the visible feed's filter so the CSV matches what the user sees.
  const exportFeed = useActivityFeed({ category: feedCategory, tenantIds });

  // Toast on summary fetch errors so users don't see indefinite "—" skeletons.
  React.useEffect(() => {
    if (summary.isError) {
      toast({
        variant: "destructive",
        title: "Activity summary를 불러오지 못했습니다",
        description: "잠시 후 자동 재시도합니다.",
      });
    }
  }, [summary.isError, toast]);

  function toggleTenant(id: string) {
    setTenantIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  async function handleExport() {
    if (exporting) return;
    setExporting(true);
    try {
      let rows = exportFeed.data?.pages.flatMap((p) => p.items) ?? [];
      let hasNext = exportFeed.hasNextPage;
      let safety = 0;
      while (hasNext && rows.length < MAX_EXPORT_ROWS && safety < 200) {
        const next = await exportFeed.fetchNextPage();
        rows = next.data?.pages.flatMap((p) => p.items) ?? [];
        hasNext = !!next.hasNextPage;
        safety++;
      }
      if (rows.length === 0) {
        toast({ variant: "default", title: "내보낼 이벤트가 없습니다." });
        return;
      }
      if (rows.length >= MAX_EXPORT_ROWS) {
        toast({
          variant: "default",
          title: `상위 ${MAX_EXPORT_ROWS}건만 내보냈습니다.`,
          description: "기간 또는 tenant 필터를 좁힌 뒤 다시 시도해 주세요.",
        });
      }
      const csv = rowsToCsv(rows.slice(0, MAX_EXPORT_ROWS), [
        { key: "createdAt", header: "createdAt" },
        { key: "eventType", header: "eventType" },
        { key: "category", header: "category" },
        { key: "tenantName", header: "tenantName" },
        { key: "tenantId", header: "tenantId" },
        { key: "actorType", header: "actorType" },
        { key: "actorIdShort", header: "actorIdShort" },
        { key: "subjectType", header: "subjectType" },
        { key: "subjectIdShort", header: "subjectIdShort" },
      ]);
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      downloadCsv(`activity-${stamp}.csv`, csv);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[22px] font-semibold">Activity</h1>
          <p className="text-[13px] text-text-mute">
            전체 tenant의 ceremony · 운영 액션 · 보안 이벤트가 실시간으로 모입니다.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => summary.refetch()}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12px] font-medium"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            <RefreshCw className="h-3.5 w-3.5" /> 새로고침
          </button>
          <button
            type="button"
            disabled={exporting}
            onClick={handleExport}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12px] font-medium disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            <Download className="h-3.5 w-3.5" /> {exporting ? "내보내는 중…" : "내보내기"}
          </button>
        </div>
      </div>
      <ActivityMetricsRow summary={summary.data} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <ActivityFeedPanel
          tenantIds={tenantIds}
          category={feedCategory}
          onCategoryChange={setFeedCategory}
        />
        <ActiveTenantsPanel rows={summary.data?.topTenants ?? []} />
      </div>
      <TenantFilterChips
        options={summary.data?.topTenants ?? []}
        selected={tenantIds}
        onToggle={toggleTenant}
        onClear={() => setTenantIds([])}
      />
    </div>
  );
}
