import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { apiGet } from "@/lib/api";
import { formatCount, formatDateTime } from "@/lib/format";
import type { EndUserView, PageResponse } from "@/types/api";

/** Debounce a fast-changing value (e.g. a search box) — local copy of the CredentialsTab helper. */
function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

export function UsersTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const [page, setPage] = React.useState(0);
  const size = 50;
  const [search, setSearch] = React.useState("");
  const debouncedSearch = useDebounced(search, 300);

  // Reset to the first page whenever the search term changes.
  React.useEffect(() => {
    setPage(0);
  }, [debouncedSearch]);

  const { data, isLoading } = useQuery({
    queryKey: ["endUsers", tenantId, { page, size, q: debouncedSearch }],
    queryFn: () => {
      const q = debouncedSearch.trim();
      const qParam = q.length === 0 ? "" : `&q=${encodeURIComponent(q)}`;
      return apiGet<PageResponse<EndUserView>>(
        `/api/v1/admin/tenants/${tenantId}/users?page=${page}&size=${size}${qParam}`,
      );
    },
    enabled: !!tenantId,
  });

  const users = data?.content ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Users"
        description="이 tenant의 end-user(tenant_user) 목록. externalId 또는 표시 이름으로 검색."
      />

      <div className="relative max-w-sm">
        <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
        <Input
          className="pl-8"
          placeholder="externalId / 표시 이름 검색"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">불러오는 중…</p>
      ) : users.length === 0 ? (
        <EmptyState title="조건에 맞는 사용자가 없습니다." />
      ) : (
        <>
          <p className="text-xs text-muted-foreground">
            {formatCount(data?.totalElements ?? users.length)}명
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>External ID</TableHead>
                <TableHead>표시 이름</TableHead>
                <TableHead>활성 Passkey</TableHead>
                <TableHead>생성</TableHead>
                <TableHead>수정</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => (
                <TableRow
                  key={u.id}
                  className="cursor-pointer"
                  onClick={() => navigate(`/tenants/${tenantId}/users/${u.id}`)}
                >
                  <TableCell className="font-mono text-xs">{u.externalId}</TableCell>
                  <TableCell>{u.displayName ?? "—"}</TableCell>
                  <TableCell>{formatCount(u.activeCredentialCount)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(u.createdAt)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(u.updatedAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          <div className="flex items-center justify-between pt-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!data?.hasPrevious}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              이전
            </Button>
            <span className="text-xs text-muted-foreground">
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
        </>
      )}
    </div>
  );
}
