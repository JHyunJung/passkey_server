import * as React from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { apiGet } from "@/lib/api";
import { formatCount, formatDateTime, lastN } from "@/lib/format";
import type { EndUserDetailView } from "@/types/api";

export function UserDetailPage() {
  const { tenantId, tenantUserId } = useParams<{
    tenantId: string;
    tenantUserId: string;
  }>();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["endUser", tenantId, tenantUserId],
    queryFn: () =>
      apiGet<EndUserDetailView>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }
  if (isError || !data) {
    return <EmptyState title="사용자를 찾을 수 없습니다." />;
  }

  return (
    <div className="space-y-5">
      <Link
        to={`/tenants/${tenantId}/users`}
        className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="h-3.5 w-3.5" /> 사용자 목록
      </Link>

      <PageHeader
        title={data.displayName ?? data.externalId}
        description={`External ID: ${data.externalId}`}
      />

      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Meta label="내부 ID" value={lastN(data.id, 8)} mono />
        <Meta label="활성 Passkey" value={formatCount(data.activeCredentialCount)} />
        <Meta label="생성" value={formatDateTime(data.createdAt)} />
        <Meta
          label="최근 활동"
          value={data.lastActivityAt ? formatDateTime(data.lastActivityAt) : "—"}
        />
      </div>

      <div className="space-y-2">
        <h2 className="text-sm font-semibold">Passkeys</h2>
        {data.credentials.length === 0 ? (
          <EmptyState title="등록된 passkey가 없습니다." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Credential ID</TableHead>
                <TableHead>닉네임</TableHead>
                <TableHead>상태</TableHead>
                <TableHead>마지막 사용</TableHead>
                <TableHead>생성</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.credentials.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-xs">{lastN(c.credentialId, 12)}</TableCell>
                  <TableCell>{c.nickname ?? "—"}</TableCell>
                  <TableCell>
                    <Badge variant={c.status === "ACTIVE" ? "success" : "destructive"}>
                      {c.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {c.lastUsedAt ? formatDateTime(c.lastUsedAt) : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(c.createdAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}

function Meta({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={mono ? "mt-0.5 font-mono text-sm" : "mt-0.5 text-sm"}>{value}</div>
    </div>
  );
}
