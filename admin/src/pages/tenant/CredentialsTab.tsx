import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Fingerprint,
  MoreHorizontal,
  Pencil,
  Search,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useMe } from "@/hooks/useMe";
import { CredentialStatsPanel } from "./credentials/CredentialStatsPanel";
import { ForceLogoutDialog } from "./credentials/ForceLogoutDialog";
import { ReassignDialog } from "./credentials/ReassignDialog";
import type { TenantView } from "@/types/api";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { apiDelete, apiGet, apiPatch, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { cn } from "@/lib/cn";
import { formatDateTime, lastN } from "@/lib/format";
import {
  CREDENTIAL_REVOKED_REASONS,
  type CredentialRevokedReason,
  type CredentialView,
  type PageResponse,
} from "@/types/api";

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

export function CredentialsTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const qc = useQueryClient();
  const { toast } = useToast();
  const [page, setPage] = React.useState(0);
  const size = 50;
  const [search, setSearch] = React.useState("");
  const debouncedSearch = useDebounced(search, 300);

  // Reset to first page when the search term changes.
  React.useEffect(() => {
    setPage(0);
  }, [debouncedSearch]);

  const { data, isLoading } = useQuery({
    queryKey: ["credentials", tenantId, { page, size, q: debouncedSearch }],
    queryFn: () => {
      const q = debouncedSearch.trim();
      const qParam = q.length === 0 ? "" : `&q=${encodeURIComponent(q)}`;
      return apiGet<PageResponse<CredentialView>>(
        `/api/v1/admin/tenants/${tenantId}/credentials?page=${page}&size=${size}${qParam}`,
      );
    },
    enabled: !!tenantId,
  });

  // Server-side filter (P2-4) — data.content is already filtered. Memoised so its identity is
  // stable across renders, otherwise the `credentialCountForUser` useCallback below would be
  // rebuilt every render (rerender-derived-state-no-effect / exhaustive-deps).
  const filtered = React.useMemo(() => data?.content ?? [], [data?.content]);

  const { data: me } = useMe();
  const isPlatform = me?.role === "PLATFORM_OPERATOR";
  const [revokeTarget, setRevokeTarget] = React.useState<CredentialView | null>(null);
  const [revokeReason, setRevokeReason] = React.useState<CredentialRevokedReason>("ADMIN_FORCED");
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [editingValue, setEditingValue] = React.useState("");
  const [forceLogoutUserId, setForceLogoutUserId] = React.useState<string | null>(null);
  const [reassignTarget, setReassignTarget] = React.useState<CredentialView | null>(null);

  const { data: tenant } = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiGet<TenantView>(`/api/v1/admin/tenants/${tenantId}`),
    enabled: !!tenantId && isPlatform,
  });

  // Same-page count of how many credentials this user has — informational only; not authoritative.
  const credentialCountForUser = React.useCallback(
    (userId: string) => filtered.filter((c) => c.tenantUserId === userId).length,
    [filtered],
  );

  const rename = useMutation({
    mutationFn: (args: { credentialDbId: string; nickname: string }) =>
      apiPatch<CredentialView>(
        `/api/v1/admin/tenants/${tenantId}/credentials/${args.credentialDbId}/nickname`,
        { nickname: args.nickname },
      ),
    onSuccess: () => {
      toast({ variant: "success", title: "Nickname이 변경되었습니다." });
      qc.invalidateQueries({ queryKey: ["credentials", tenantId] });
      setEditingId(null);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  function startEdit(c: CredentialView) {
    setEditingId(c.id);
    setEditingValue(c.nickname ?? "");
  }
  function commitEdit() {
    if (editingId) {
      rename.mutate({ credentialDbId: editingId, nickname: editingValue });
    }
  }
  function cancelEdit() {
    setEditingId(null);
    setEditingValue("");
  }

  const revoke = useMutation({
    mutationFn: (args: { credentialDbId: string; reason: CredentialRevokedReason }) =>
      apiDelete<void>(
        `/api/v1/admin/tenants/${tenantId}/credentials/${args.credentialDbId}?reason=${args.reason}`,
      ),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["credentials", tenantId] });
      toast({ variant: "success", title: "Credential이 회수되었습니다." });
      setRevokeTarget(null);
      setRevokeReason("ADMIN_FORCED");
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  return (
    <div className="space-y-4">
      <PageHeader
        title="Credentials"
        description="등록된 Passkey 자격증명. 의심스러운 항목은 회수하세요."
      />

      <CredentialStatsPanel tenantId={tenantId!} />

      {isLoading ? (
        <p className="text-sm text-muted-foreground">불러오는 중…</p>
      ) : !data || data.content.length === 0 ? (
        <EmptyState title="등록된 credential이 없습니다." />
      ) : (
        <div
          className="overflow-hidden rounded-lg border"
          style={{
            background: "var(--surface)",
            borderColor: "var(--border-subtle)",
            boxShadow: "var(--shadow-xs)",
          }}
        >
          {/* Card head — search + result count */}
          <div
            className="flex flex-wrap items-center justify-between gap-3 px-5 py-3"
            style={{ borderBottom: "1px solid var(--border-subtle)" }}
          >
            <div className="flex flex-1 items-center gap-2.5">
              <div className="relative w-full max-w-[360px]">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2"
                  style={{ color: "var(--text-mute)" }}
                />
                <Input
                  placeholder="tenantUserId · credentialId · nickname 검색"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="h-8 pl-8 text-[13px]"
                />
              </div>
              <span
                className="text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                {data.totalElements}건
              </span>
            </div>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Credential ID</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Nickname</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>AAGUID</TableHead>
                <TableHead>Transports</TableHead>
                <TableHead>Counter</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead className="w-24 text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((c) => {
                const revoked = c.status === "REVOKED";
                return (
                  <TableRow
                    key={c.id}
                    className={cn(revoked && "opacity-60 text-muted-foreground")}
                  >
                    <TableCell className="font-mono text-xs">
                      {lastN(c.credentialId, 12)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {lastN(c.tenantUserId, 8)}
                    </TableCell>
                    <TableCell>
                      {editingId === c.id ? (
                        <div className="flex items-center gap-1">
                          <Input
                            autoFocus
                            value={editingValue}
                            onChange={(e) => setEditingValue(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") commitEdit();
                              if (e.key === "Escape") cancelEdit();
                            }}
                            className="h-7 text-xs"
                          />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={commitEdit}
                            disabled={rename.isPending}
                            aria-label="저장"
                          >
                            <Check className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={cancelEdit}
                            aria-label="취소"
                          >
                            <X className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          className="group flex items-center gap-1 text-left"
                          onClick={() => startEdit(c)}
                          disabled={revoked}
                        >
                          <span>{c.nickname ?? "—"}</span>
                          {!revoked && (
                            <Pencil className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-50" />
                          )}
                        </button>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={revoked ? "default" : "success"}
                        className="gap-1"
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: "currentColor" }}
                        />
                        {c.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {c.aaguid ? (
                        <span className="inline-flex items-center gap-1.5">
                          <Fingerprint
                            className="h-3 w-3"
                            style={{ color: "var(--text-mute)" }}
                          />
                          {lastN(c.aaguid, 8)}
                        </span>
                      ) : (
                        "—"
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      {c.transports ? (
                        <span className="inline-flex flex-wrap gap-1">
                          {c.transports.split(",").map((t) => (
                            <Badge
                              key={t.trim()}
                              variant="default"
                              className="text-[10px] uppercase"
                            >
                              {t.trim()}
                            </Badge>
                          ))}
                        </span>
                      ) : (
                        "—"
                      )}
                    </TableCell>
                    <TableCell>{c.signatureCounter}</TableCell>
                    <TableCell className="text-xs">{formatDateTime(c.lastUsedAt)}</TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label="작업 메뉴"
                          >
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-56">
                          {!revoked && (
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              onSelect={() => setRevokeTarget(c)}
                            >
                              Credential 회수
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem
                            onSelect={() => setForceLogoutUserId(c.tenantUserId)}
                          >
                            이 사용자의 모든 세션 종료
                          </DropdownMenuItem>
                          {isPlatform && !revoked && (
                            <>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onSelect={() => setReassignTarget(c)}>
                                다른 tenant로 이관
                              </DropdownMenuItem>
                            </>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          <div
            className="flex items-center justify-between px-4 py-2.5 text-[12px]"
            style={{
              color: "var(--text-mute)",
              borderTop: "1px solid var(--border-subtle)",
            }}
          >
            <span>
              page {data.page + 1} of {data.totalPages || 1} · 페이지당 {size}건 · 총{" "}
              {data.totalElements}건
            </span>
            {data.totalPages > 1 && (
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!data.hasPrevious}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                >
                  이전
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!data.hasNext}
                  onClick={() => setPage((p) => p + 1)}
                >
                  다음
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      <Dialog open={!!revokeTarget} onOpenChange={(open) => !open && setRevokeTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Credential 회수</DialogTitle>
            <DialogDescription>
              회수된 credential로는 더 이상 인증할 수 없습니다. 사용자의 활성 refresh token도 함께
              회수됩니다.
            </DialogDescription>
          </DialogHeader>
          {revokeTarget && (
            <div className="space-y-3">
              <div className="rounded-md border bg-muted/40 p-3 font-mono text-xs">
                Credential ID: {lastN(revokeTarget.credentialId, 12)}
                <br />
                User: {lastN(revokeTarget.tenantUserId, 8)}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="revokeReason">회수 사유</Label>
                <Select
                  value={revokeReason}
                  onValueChange={(v) => setRevokeReason(v as CredentialRevokedReason)}
                >
                  <SelectTrigger id="revokeReason">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CREDENTIAL_REVOKED_REASONS.map((r) => (
                      <SelectItem key={r} value={r}>
                        {r}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  사용자/CS 안내 메시지에 표시되며 audit log에 영구 기록됩니다.
                </p>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeTarget(null)}>
              취소
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                revokeTarget &&
                revoke.mutate({ credentialDbId: revokeTarget.id, reason: revokeReason })
              }
              disabled={revoke.isPending}
            >
              {revoke.isPending ? "회수 중…" : "회수"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ForceLogoutDialog
        tenantId={tenantId!}
        tenantUserId={forceLogoutUserId}
        affectedCredentialCount={
          forceLogoutUserId ? credentialCountForUser(forceLogoutUserId) : 0
        }
        onOpenChange={(open) => !open && setForceLogoutUserId(null)}
      />

      <ReassignDialog
        sourceTenantId={tenantId!}
        sourceTenantSlug={tenant?.slug}
        target={reassignTarget}
        onOpenChange={(open) => !open && setReassignTarget(null)}
      />
    </div>
  );
}
