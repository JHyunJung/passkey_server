import * as React from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { ChevronRight, Plus, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/EmptyState";
import { MetricCard } from "@/components/MetricCard";
import { PageHeader } from "@/components/PageHeader";
import { apiGet, apiPost, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import type { CreateTenantRequest, PageResponse, TenantView } from "@/types/api";

const tenantsKey = (page: number, size: number) =>
  ["tenants", { page, size }] as const;

export function TenantsListPage() {
  const [page, setPage] = React.useState(0);
  const [q, setQ] = React.useState("");
  const size = 50;
  const { data, isLoading } = useQuery({
    queryKey: tenantsKey(page, size),
    queryFn: () =>
      apiGet<PageResponse<TenantView>>(
        `/api/v1/admin/tenants?page=${page}&size=${size}`,
      ),
  });
  const [createOpen, setCreateOpen] = React.useState(false);

  const all = data?.content ?? [];
  const activeCount = all.filter((t) => t.status === "ACTIVE").length;
  const totalCount = data?.totalElements ?? all.length;
  const filtered = React.useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return all;
    return all.filter(
      (t) =>
        t.name.toLowerCase().includes(needle) ||
        t.slug.toLowerCase().includes(needle),
    );
  }, [q, all]);

  return (
    <>
      <PageHeader
        title="Tenants"
        description="RP 회사별 격리된 Passkey 환경. 모든 데이터는 tenant_id로 row-level 분리되어 있습니다."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1.5 h-3.5 w-3.5" /> 신규 tenant
          </Button>
        }
      />

      {/* Metric strip — only "활성 Tenant" reflects live data; the other three
          are visual scaffolding from the handoff design until backend stats land. */}
      <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="활성 Tenant"
          value={isLoading ? "…" : activeCount}
          sub={`전체 ${totalCount}건`}
        />
        <MetricCard label="등록 Credential" value="—" sub="합산 지표 미연동" />
        <MetricCard label="유효 API Key" value="—" sub="합산 지표 미연동" />
        <MetricCard label="24h ceremony" value="—" sub="합산 지표 미연동" />
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">불러오는 중…</p>
      ) : all.length === 0 ? (
        <EmptyState
          title="아직 등록된 tenant가 없습니다."
          description='상단의 "신규 tenant" 버튼으로 첫 RP를 온보딩하세요.'
        />
      ) : (
        <div
          className="overflow-hidden rounded-lg border"
          style={{
            background: "var(--surface)",
            borderColor: "var(--border-subtle)",
            boxShadow: "var(--shadow-xs)",
          }}
        >
          {/* Card head — search + counter */}
          <div
            className="flex items-center justify-between gap-3 px-5 py-3"
            style={{ borderBottom: "1px solid var(--border-subtle)" }}
          >
            <div className="flex items-center gap-2.5">
              <div className="relative w-[280px]">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2"
                  style={{ color: "var(--text-mute)" }}
                />
                <Input
                  placeholder="name · slug 검색"
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  className="h-8 pl-8 text-[13px]"
                />
              </div>
              <span className="text-[12px]" style={{ color: "var(--text-mute)" }}>
                {filtered.length} / {all.length}건
              </span>
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tenant</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((t) => (
                <TenantRow key={t.id} t={t} />
              ))}
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
              page {data ? data.page + 1 : 1} of {data?.totalPages ?? 1} ·{" "}
              {totalCount}건
            </span>
            {data && data.totalPages > 1 && (
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

      <CreateTenantDialog open={createOpen} onOpenChange={setCreateOpen} />
    </>
  );
}

function TenantRow({ t }: { t: TenantView }) {
  const initial = t.name.slice(0, 1).toUpperCase();
  const tail = t.id.length <= 8 ? t.id : `…${t.id.slice(-8)}`;
  return (
    <TableRow className="cursor-pointer">
      <TableCell>
        <Link to={`/tenants/${t.id}/overview`} className="flex items-center gap-2.5">
          <div
            className="grid h-[26px] w-[26px] shrink-0 place-items-center rounded text-[11px] font-bold"
            style={{ background: "var(--accent-soft)", color: "var(--accent)" }}
          >
            {initial}
          </div>
          <div className="min-w-0">
            <div className="font-semibold" style={{ color: "var(--text)" }}>
              {t.name}
            </div>
            <div
              className="font-mono text-[11px]"
              style={{ color: "var(--text-mute)" }}
            >
              {tail}
            </div>
          </div>
        </Link>
      </TableCell>
      <TableCell className="font-mono text-[13px]">{t.slug}</TableCell>
      <TableCell>
        <Badge
          variant={t.status === "ACTIVE" ? "success" : "default"}
          className="gap-1"
        >
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: "currentColor" }}
          />
          {t.status}
        </Badge>
      </TableCell>
      <TableCell>
        <Link
          to={`/tenants/${t.id}/overview`}
          aria-label="열기"
          className="inline-flex items-center justify-center rounded p-1 hover:bg-surface-3"
          style={{ color: "var(--text-mute)" }}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Link>
      </TableCell>
    </TableRow>
  );
}

const createSchema = z.object({
  name: z.string().min(1, "이름을 입력하세요").max(100),
  slug: z
    .string()
    .regex(
      /^[a-z][a-z0-9-]{1,62}$/,
      "소문자/숫자/하이픈만 사용 (소문자로 시작, 2~63자)",
    ),
});

function CreateTenantDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<CreateTenantRequest>({ resolver: zodResolver(createSchema) });

  const create = useMutation({
    mutationFn: (data: CreateTenantRequest) =>
      apiPost<TenantView>("/api/v1/admin/tenants", data),
    onSuccess: () => {
      toast({ variant: "success", title: "Tenant가 생성되었습니다." });
      qc.invalidateQueries({ queryKey: ["tenants"] });
      reset();
      onOpenChange(false);
    },
    onError: (e: PasskeyAdminError) => {
      if (e.code === "T004") {
        setError("slug", { message: "이미 사용 중인 slug입니다." });
        return;
      }
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>신규 tenant 생성</DialogTitle>
          <DialogDescription>
            slug는 URL/헤더용 식별자입니다. 생성 후에는 변경할 수 없습니다.
          </DialogDescription>
        </DialogHeader>
        <form
          id="create-tenant-form"
          onSubmit={handleSubmit((d) => create.mutate(d))}
          className="space-y-4"
        >
          <div className="space-y-1.5">
            <Label htmlFor="name">이름</Label>
            <Input id="name" autoFocus {...register("name")} />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name.message}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="slug">Slug</Label>
            <Input id="slug" placeholder="example-card" {...register("slug")} />
            {errors.slug && (
              <p className="text-xs text-destructive">{errors.slug.message}</p>
            )}
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button
            type="submit"
            form="create-tenant-form"
            disabled={isSubmitting || create.isPending}
          >
            {create.isPending ? "생성 중…" : "생성"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
