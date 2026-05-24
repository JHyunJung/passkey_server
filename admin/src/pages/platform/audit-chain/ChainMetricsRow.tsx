import { MetricCard } from "@/components/MetricCard";
import type { AuditChainStatus } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

function fmt(n: number | null | undefined): string {
  return n == null ? "—" : nf.format(Math.round(n));
}

export function ChainMetricsRow({ status }: { status?: AuditChainStatus }) {
  if (!status) {
    return (
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <MetricCard key={i} label="로딩 중" value="—" />
        ))}
      </div>
    );
  }
  const intactSub =
    status.tamperedTenants.length > 0
      ? `위변조 의심: ${status.tamperedTenants.map((t) => t.name).join(", ")}`
      : "모든 tenant 무결";
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
      <MetricCard
        label="무결 / 전체"
        value={`${status.intactTenants} / ${status.totalTenants}`}
        sub={intactSub}
      />
      <MetricCard
        label="검증된 audit row"
        value={nf.format(status.totalVerifiedRows)}
        sub="누적 chain length"
      />
      <MetricCard
        label="검증 주기"
        value={status.schedulerCron}
        sub={`scheduler · 어드민 새로고침 ${status.adminPollingIntervalSec}s`}
      />
      <MetricCard
        label="평균 chain 검증"
        value={`${fmt(status.lastVerifyAvgMs)}ms`}
        sub={`p99 ${fmt(status.lastVerifyP99Ms)}ms`}
      />
    </div>
  );
}
