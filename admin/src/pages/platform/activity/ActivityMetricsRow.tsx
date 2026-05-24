import { MetricCard } from "@/components/MetricCard";
import type { ActivitySummary } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

function fmt(n: number | null | undefined): string {
  return n == null ? "—" : nf.format(Math.round(n));
}

export function ActivityMetricsRow({ summary }: { summary?: ActivitySummary }) {
  const activity24h = summary ? nf.format(summary.activity24h) : "—";
  const adminMutations24h = summary ? nf.format(summary.adminMutations24h) : "—";
  const securityEvents24h = summary ? nf.format(summary.securityEvents24h) : "—";
  const avg = summary?.latency.avgMs;
  const p95 = summary?.latency.p95Ms;
  const p99 = summary?.latency.p99Ms;
  const latencyValue = avg == null ? "—" : `${Math.round(avg)}ms`;
  const latencySub =
    p95 == null && p99 == null
      ? "메트릭 워밍업 중"
      : `p95 ${fmt(p95)}ms · p99 ${fmt(p99)}ms`;
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
      <MetricCard
        label="활동 (24H)"
        value={activity24h}
        sub={summary ? `${summary.topTenants.length}개 tenant 합산` : ""}
      />
      <MetricCard
        label="운영 액션 (24H)"
        value={adminMutations24h}
        sub="admin mutation 전체"
      />
      <MetricCard
        label="보안 이벤트 (24H)"
        value={securityEvents24h}
        sub="signature regression + attestation fail"
      />
      <MetricCard label="평균 응답" value={latencyValue} sub={latencySub} />
    </div>
  );
}
