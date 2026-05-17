import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { apiGet, apiPost, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { formatDateTime } from "@/lib/format";
import type { MdsStatusView } from "@/types/api";

const QUERY_KEY = ["system", "mds"] as const;

export function MdsCard() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [confirmOpen, setConfirmOpen] = React.useState(false);

  const { data, isLoading } = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => apiGet<MdsStatusView>("/api/v1/admin/system/mds/status"),
  });

  const refresh = useMutation({
    mutationFn: () => apiPost<MdsStatusView>("/api/v1/admin/system/mds/refresh"),
    onSuccess: (next) => {
      qc.setQueryData(QUERY_KEY, next);
      toast({ variant: "success", title: "MDS 갱신 완료" });
      setConfirmOpen(false);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
      setConfirmOpen(false);
    },
  });

  const statusBadge = (() => {
    if (!data) return null;
    if (data.status === "READY") return <Badge variant="success">READY</Badge>;
    if (data.status === "NEVER_FETCHED") return <Badge variant="warning">NEVER_FETCHED</Badge>;
    return <Badge variant="secondary">DISABLED</Badge>;
  })();

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-start justify-between space-y-0">
          <div>
            <CardTitle>FIDO MDS3</CardTitle>
            <p className="text-xs text-muted-foreground">
              인증기 메타데이터 BLOB · 자동 갱신 cron: {data?.refreshCron ?? "—"}
            </p>
          </div>
          {statusBadge}
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          {isLoading ? (
            <div className="animate-pulse rounded-md bg-muted/40 p-4 text-xs text-muted-foreground">
              불러오는 중…
            </div>
          ) : (
            <dl className="grid grid-cols-2 gap-y-1 text-xs">
              <dt className="text-muted-foreground">enabled</dt>
              <dd>{String(data?.enabled ?? false)}</dd>
              <dt className="text-muted-foreground">lastFetched</dt>
              <dd>{formatDateTime(data?.lastFetched ?? null)}</dd>
              <dt className="text-muted-foreground">entryCount</dt>
              <dd>{data?.entryCount ?? "—"}</dd>
              <dt className="text-muted-foreground">nextUpdate</dt>
              <dd>{data?.nextUpdate ?? "—"}</dd>
              <dt className="text-muted-foreground">serialNumber</dt>
              <dd>{data?.serialNumber ?? "—"}</dd>
              <dt className="text-muted-foreground">blobUrl</dt>
              <dd className="truncate font-mono" title={data?.blobUrl ?? ""}>
                {data?.blobUrl ?? "—"}
              </dd>
            </dl>
          )}
          <div className="flex justify-end pt-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!data?.enabled || refresh.isPending}
              onClick={() => setConfirmOpen(true)}
            >
              <RefreshCw className="mr-1 h-3.5 w-3.5" />
              지금 갱신
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>FIDO MDS BLOB 강제 갱신</DialogTitle>
            <DialogDescription>
              FIDO MDS BLOB를 즉시 다시 가져옵니다. 평소엔 매일 자동 갱신되며, 강제 갱신은
              네트워크 RTT만큼 응답이 지연될 수 있습니다.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              취소
            </Button>
            <Button onClick={() => refresh.mutate()} disabled={refresh.isPending}>
              {refresh.isPending ? "갱신 중…" : "지금 갱신"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
