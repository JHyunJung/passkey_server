import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { Segmented } from "@/components/Segmented";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { apiGet, apiDelete, apiPost, PasskeyAdminError } from "@/lib/api";
import type {
  PageResponse,
  RefreshTokenView,
  RevokeRefreshTokenResult,
} from "@/types/api";
import { useToast } from "@/hooks/useToast";
import { formatDateTime, lastN } from "@/lib/format";

const PAGE_SIZE = 20;

interface Props {
  tenantId: string;
  tenantUserId: string;
}

type StatusFilter = "active" | "all";

const FILTER_OPTIONS: ReadonlyArray<StatusFilter> = ["active", "all"];
const FILTER_LABEL: Record<StatusFilter, string> = {
  active: "활성만",
  all: "전체",
};

export function SessionsTabPanel({ tenantId, tenantUserId }: Props) {
  const [page, setPage] = React.useState(0);
  const [statusFilter, setStatusFilter] = React.useState<StatusFilter>("active");
  const [confirmId, setConfirmId] = React.useState<string | null>(null);
  const [logoutAllOpen, setLogoutAllOpen] = React.useState(false);
  const qc = useQueryClient();
  const { toast } = useToast();

  React.useEffect(() => setPage(0), [statusFilter]);

  const queryKey = ["userRefreshTokens", tenantId, tenantUserId, page, statusFilter];
  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: () =>
      apiGet<PageResponse<RefreshTokenView>>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/refresh-tokens` +
          `?status=${statusFilter}&page=${page}&size=${PAGE_SIZE}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  const revokeOne = useMutation({
    mutationFn: (tokenId: string) =>
      apiDelete<RevokeRefreshTokenResult>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/refresh-tokens/${tokenId}`,
      ),
    onSuccess: (res) => {
      toast({
        variant: res?.alreadyRevoked ? "default" : "success",
        title: res?.alreadyRevoked
          ? "이미 회수된 세션입니다."
          : "세션이 회수되었습니다.",
      });
      qc.invalidateQueries({ queryKey: ["userRefreshTokens", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      setConfirmId(null);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const logoutAll = useMutation({
    mutationFn: () =>
      apiPost<{ revokedCount: number }>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/logout-all`,
      ),
    onSuccess: (res) => {
      toast({
        variant: "success",
        title: `${res?.revokedCount ?? 0}개 세션이 회수되었습니다.`,
      });
      qc.invalidateQueries({ queryKey: ["userRefreshTokens", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      setLogoutAllOpen(false);
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const rows = data?.content ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">상태:</span>
          <Segmented
            value={statusFilter}
            onChange={setStatusFilter}
            options={FILTER_OPTIONS}
          />
          <span className="text-xs text-muted-foreground">
            ({FILTER_LABEL[statusFilter]})
          </span>
        </div>
        <Button variant="destructive" onClick={() => setLogoutAllOpen(true)}>
          모두 로그아웃
        </Button>
      </div>

      {isLoading ? (
        <p>불러오는 중…</p>
      ) : rows.length === 0 ? (
        <EmptyState
          title={
            statusFilter === "active"
              ? "활성 세션이 없습니다."
              : "이 사용자의 세션 기록이 없습니다."
          }
        />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>발급</TableHead>
                <TableHead>만료</TableHead>
                <TableHead>Client</TableHead>
                <TableHead>상태</TableHead>
                <TableHead className="text-right">액션</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((t) => {
                const revoked = t.revokedAt !== null;
                // "all" 모드는 expired-but-not-revoked 토큰도 노출한다. 이런 행을 ACTIVE로
                // 표시하거나 revoke 가능하게 두면 forensic 상태가 ADMIN_FORCED로 오염되므로,
                // 만료 시점을 클라이언트에서 별도 판정해 EXPIRED 배지 + 액션 비활성화한다.
                const expired = !revoked && new Date(t.expiresAt).getTime() <= Date.now();
                return (
                  <TableRow key={t.id}>
                    <TableCell>{formatDateTime(t.issuedAt)}</TableCell>
                    <TableCell>{formatDateTime(t.expiresAt)}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {t.clientIp ?? "—"}
                      {t.userAgent ? ` · ${lastN(t.userAgent, 24)}` : ""}
                    </TableCell>
                    <TableCell>
                      {revoked ? (
                        <Badge variant="outline">{t.revokedReason ?? "REVOKED"}</Badge>
                      ) : expired ? (
                        <Badge variant="outline">EXPIRED</Badge>
                      ) : (
                        <Badge variant="success">ACTIVE</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {!revoked && !expired && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setConfirmId(t.id)}
                        >
                          회수
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>

          <div className="flex items-center justify-between pt-2">
            <Button
              disabled={!data?.hasPrevious}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              이전
            </Button>
            <span>
              {(data?.page ?? 0) + 1} / {data?.totalPages ?? 1}
            </span>
            <Button
              disabled={!data?.hasNext}
              onClick={() => setPage((p) => p + 1)}
            >
              다음
            </Button>
          </div>
        </>
      )}

      <ConfirmDialog
        open={confirmId !== null}
        title="세션 회수"
        description="이 기기의 세션을 즉시 종료합니다. 사용자는 해당 기기에서 다시 로그인해야 합니다."
        destructive
        confirmLabel="회수"
        busy={revokeOne.isPending}
        onConfirm={() => confirmId && revokeOne.mutate(confirmId)}
        onOpenChange={(o) => {
          if (!o) setConfirmId(null);
        }}
      />

      <ConfirmDialog
        open={logoutAllOpen}
        title="모든 세션 로그아웃"
        description="이 사용자의 모든 활성 세션을 종료합니다. 모든 기기에서 즉시 다시 로그인해야 합니다."
        destructive
        confirmLabel="모두 회수"
        busy={logoutAll.isPending}
        onConfirm={() => logoutAll.mutate()}
        onOpenChange={(o) => setLogoutAllOpen(o)}
      />
    </div>
  );
}
