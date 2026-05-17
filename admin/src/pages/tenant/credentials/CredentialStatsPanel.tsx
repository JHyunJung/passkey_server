import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiGet } from "@/lib/api";
import { lastN } from "@/lib/format";
import type { CredentialStatsView } from "@/types/api";

interface Props {
  tenantId: string;
}

const TOP_N = 5;

export function CredentialStatsPanel({ tenantId }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["credentialStats", tenantId],
    queryFn: () =>
      apiGet<CredentialStatsView>(`/api/v1/admin/tenants/${tenantId}/credentials/stats`),
    enabled: !!tenantId,
  });

  if (isLoading || !data) {
    return (
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <SkeletonCard title="AAGUID 분포" />
        <SkeletonCard title="상태 분포" />
      </div>
    );
  }

  const aaguidTop = data.aaguid.slice(0, TOP_N);
  const aaguidOther = data.aaguid.slice(TOP_N).reduce((acc, x) => acc + x.count, 0);
  const aaguidTotal = data.aaguid.reduce((acc, x) => acc + x.count, 0);

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">AAGUID 분포</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-xs">
          {aaguidTotal === 0 ? (
            <p className="text-muted-foreground">데이터 없음</p>
          ) : (
            <>
              {aaguidTop.map((row) => (
                <Bar
                  key={row.aaguid}
                  label={row.aaguid === "unknown" ? "unknown" : lastN(row.aaguid, 8)}
                  count={row.count}
                  total={aaguidTotal}
                />
              ))}
              {aaguidOther > 0 && (
                <Bar label={`기타 ${data.aaguid.length - TOP_N}개`} count={aaguidOther} total={aaguidTotal} />
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">상태 / 회수 사유</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2 text-xs">
          {data.revokedReason.length === 0 ? (
            <p className="text-muted-foreground">데이터 없음</p>
          ) : (
            data.revokedReason.map((row) => (
              <Badge
                key={row.reason}
                variant={row.reason === "ACTIVE" ? "success" : "secondary"}
              >
                {row.reason} · {row.count}
              </Badge>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Bar({ label, count, total }: { label: string; count: number; total: number }) {
  const pct = Math.round((count / total) * 100);
  return (
    <div>
      <div className="flex items-center justify-between font-mono">
        <span className="truncate" title={label}>
          {label}
        </span>
        <span className="text-muted-foreground">
          {count} · {pct}%
        </span>
      </div>
      <div className="h-1.5 rounded bg-muted">
        <div className="h-1.5 rounded bg-primary" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function SkeletonCard({ title }: { title: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="animate-pulse rounded bg-muted/40 p-4 text-xs text-muted-foreground">
          불러오는 중…
        </div>
      </CardContent>
    </Card>
  );
}
