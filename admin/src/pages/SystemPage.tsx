import { MetricCard } from "@/components/MetricCard";
import { PageHeader } from "@/components/PageHeader";
import { MdsCard } from "./system/MdsCard";
import { RateLimitCard } from "./system/RateLimitCard";

// SystemPage — Platform Operator only. Top strip mirrors handoff SystemInfoTab
// (Server 버전 / API 응답 / Uptime) so the page lines up visually with the rest
// of the console. The three strip values are visual placeholders until the
// backend exposes them; the MDS + RateLimit cards below are fully live.
export function SystemPage() {
  return (
    <>
      <PageHeader
        title="시스템"
        description="플랫폼 운영자 전용. 인스턴스 단위 진단 및 강제 트리거."
      />

      <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <MetricCard
          label="Server 버전"
          value="—"
          sub="버전 endpoint 미연동"
        />
        <MetricCard
          label="API 응답 (p95)"
          value="—"
          sub="latency 지표 미연동"
        />
        <MetricCard label="Uptime" value="—" sub="uptime 지표 미연동" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <MdsCard />
        <RateLimitCard />
      </div>
    </>
  );
}
