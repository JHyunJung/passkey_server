import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import { AaguidLabel } from "@/components/AaguidLabel";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { apiDelete, apiGet, apiPost, PasskeyAdminError } from "@/lib/api";
import type { PageResponse, UserCredentialItemView } from "@/types/api";
import { useToast } from "@/hooks/useToast";
import { formatDateTime } from "@/lib/format";

const PAGE_SIZE = 20;

function statusBadgeVariant(
  status: UserCredentialItemView["status"],
): "success" | "warning" | "outline" {
  switch (status) {
    case "ACTIVE":
      return "success";
    case "SUSPENDED":
      return "warning";
    case "REVOKED":
      return "outline";
  }
}

interface Props {
  tenantId: string;
  tenantUserId: string;
}

export function CredentialsTabPanel({ tenantId, tenantUserId }: Props) {
  const [page, setPage] = React.useState(0);
  const qc = useQueryClient();
  const { toast } = useToast();
  const [confirmRow, setConfirmRow] = React.useState<UserCredentialItemView | null>(null);
  const [confirmAction, setConfirmAction] = React.useState<"revoke" | "unsuspend" | null>(
    null,
  );

  const queryKey = ["userCredentials", tenantId, tenantUserId, page] as const;
  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: () =>
      apiGet<PageResponse<UserCredentialItemView>>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/credentials?page=${page}&size=${PAGE_SIZE}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  const closeConfirm = React.useCallback(() => {
    setConfirmRow(null);
    setConfirmAction(null);
  }, []);

  const revoke = useMutation({
    mutationFn: (credentialId: string) =>
      apiDelete(`/api/v1/admin/tenants/${tenantId}/credentials/${credentialId}`),
    onSuccess: () => {
      toast({ variant: "success", title: "자격증명이 회수되었습니다." });
      qc.invalidateQueries({ queryKey: ["userCredentials", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      closeConfirm();
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const unsuspend = useMutation({
    mutationFn: (credentialId: string) =>
      apiPost<void>(
        `/api/v1/admin/tenants/${tenantId}/credentials/${credentialId}/unsuspend`,
      ),
    onSuccess: () => {
      toast({ variant: "success", title: "자격증명 정지가 해제되었습니다." });
      qc.invalidateQueries({ queryKey: ["userCredentials", tenantId, tenantUserId] });
      qc.invalidateQueries({ queryKey: ["endUser", tenantId, tenantUserId] });
      closeConfirm();
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }
  const rows = data?.content ?? [];
  if (rows.length === 0) {
    return <EmptyState title="이 사용자에게는 등록된 자격증명이 없습니다." />;
  }

  return (
    <div className="space-y-3">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>AAGUID</TableHead>
            <TableHead>상태</TableHead>
            <TableHead>닉네임</TableHead>
            <TableHead>Credential ID</TableHead>
            <TableHead>마지막 사용</TableHead>
            <TableHead>등록</TableHead>
            <TableHead className="text-right">액션</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((c) => (
            <TableRow key={c.id}>
              <TableCell>
                <AaguidLabel aaguid={c.aaguid} />
              </TableCell>
              <TableCell>
                <Badge variant={statusBadgeVariant(c.status)}>{c.status}</Badge>
              </TableCell>
              <TableCell>{c.nickname ?? "—"}</TableCell>
              <TableCell className="font-mono text-xs">
                {c.credentialIdShort ?? "—"}
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {c.lastUsedAt ? formatDateTime(c.lastUsedAt) : "—"}
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatDateTime(c.createdAt)}
              </TableCell>
              <TableCell className="space-x-2 text-right">
                {c.status === "ACTIVE" && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setConfirmRow(c);
                      setConfirmAction("revoke");
                    }}
                  >
                    회수
                  </Button>
                )}
                {c.status === "SUSPENDED" && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setConfirmRow(c);
                      setConfirmAction("unsuspend");
                    }}
                  >
                    정지 해제
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <div className="flex items-center justify-between pt-2 text-sm">
        <Button
          variant="outline"
          size="sm"
          disabled={!data?.hasPrevious}
          onClick={() => setPage((p) => Math.max(0, p - 1))}
        >
          이전
        </Button>
        <span className="text-muted-foreground">
          {(data?.page ?? 0) + 1} / {data?.totalPages ?? 1}
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={!data?.hasNext}
          onClick={() => setPage((p) => p + 1)}
        >
          다음
        </Button>
      </div>

      <ConfirmDialog
        open={confirmRow !== null}
        title={confirmAction === "revoke" ? "자격증명 회수" : "정지 해제"}
        description={
          confirmAction === "revoke"
            ? `${confirmRow?.nickname ?? confirmRow?.credentialIdShort ?? "이 자격증명"}을(를) 회수합니다. 이 자격증명으로는 더 이상 로그인할 수 없습니다.`
            : `${confirmRow?.nickname ?? confirmRow?.credentialIdShort ?? "이 자격증명"}의 정지를 해제합니다.`
        }
        destructive={confirmAction === "revoke"}
        confirmLabel={confirmAction === "revoke" ? "회수" : "해제"}
        busy={revoke.isPending || unsuspend.isPending}
        onConfirm={() => {
          if (!confirmRow) return;
          if (confirmAction === "revoke") revoke.mutate(confirmRow.id);
          else if (confirmAction === "unsuspend") unsuspend.mutate(confirmRow.id);
        }}
        onOpenChange={(open) => {
          if (!open) closeConfirm();
        }}
      />
    </div>
  );
}
