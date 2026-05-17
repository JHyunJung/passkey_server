import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiGet } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { RateLimitSnapshotView } from "@/types/api";

const RULE_ORDER = ["REGISTER", "AUTHENTICATE", "ADMIN_LOGIN", "CREDENTIAL_AUTH_VERIFY", "DEFAULT"];

export function RateLimitCard() {
  const { data, isLoading } = useQuery({
    queryKey: ["system", "rate-limit"],
    queryFn: () => apiGet<RateLimitSnapshotView>("/api/v1/admin/system/rate-limit"),
    refetchInterval: 15_000,
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>Rate Limit</CardTitle>
          <p className="text-xs text-muted-foreground">
            인메모리 카운터 · 시작 이후 누적 (15초마다 갱신)
          </p>
        </div>
        {data &&
          (data.enabled ? (
            <Badge variant="success">ENABLED</Badge>
          ) : (
            <Badge variant="secondary">DISABLED</Badge>
          ))}
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {isLoading || !data ? (
          <div className="animate-pulse rounded-md bg-muted/40 p-4 text-xs text-muted-foreground">
            불러오는 중…
          </div>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">
              집계 시작: {formatDateTime(data.since)} (인스턴스 재시작 시 리셋)
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead className="text-right">Limit / min</TableHead>
                  <TableHead className="text-right">Denied (누적)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {RULE_ORDER.map((rule) => {
                  const limit = data.limits[rule];
                  const deny = data.denyCount[rule] ?? 0;
                  return (
                    <TableRow key={rule}>
                      <TableCell className="font-mono text-xs">{rule}</TableCell>
                      <TableCell className="text-right">{limit ?? "—"}</TableCell>
                      <TableCell className="text-right">
                        {deny > 0 ? (
                          <Badge variant="warning">{deny}</Badge>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </>
        )}
      </CardContent>
    </Card>
  );
}
