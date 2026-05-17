import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { CopyButton } from "@/components/CopyButton";
import { EmptyState } from "@/components/EmptyState";
import { MetricCard } from "@/components/MetricCard";
import { PageHeader } from "@/components/PageHeader";
import { useMe } from "@/hooks/useMe";
import { useToast } from "@/hooks/useToast";
import { apiDelete, apiGet, apiPost, PasskeyAdminError } from "@/lib/api";
import { formatDateTime, lastN } from "@/lib/format";
import type {
  AdminRole,
  AdminUserView,
  CreateAdminRequest,
  CreatedAdminView,
  PageResponse,
  ResetPasswordView,
} from "@/types/api";

export function AdminUsersPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { data: me } = useMe();
  const [page, setPage] = React.useState(0);
  const size = 50;

  const { data, isLoading } = useQuery({
    queryKey: ["admins", { page, size }],
    queryFn: () =>
      apiGet<PageResponse<AdminUserView>>(`/api/v1/admin/admins?page=${page}&size=${size}`),
  });

  const [createOpen, setCreateOpen] = React.useState(false);
  const [issued, setIssued] = React.useState<CreatedAdminView | null>(null);
  const [resetTarget, setResetTarget] = React.useState<AdminUserView | null>(null);
  const [resetIssued, setResetIssued] = React.useState<{
    admin: AdminUserView;
    temporaryPassword: string;
  } | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<AdminUserView | null>(null);

  const reset = useMutation({
    mutationFn: (admin: AdminUserView) =>
      apiPost<ResetPasswordView>(`/api/v1/admin/admins/${admin.id}/password`),
    onSuccess: (result, admin) => {
      setResetTarget(null);
      setResetIssued({ admin, temporaryPassword: result.temporaryPassword });
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const remove = useMutation({
    mutationFn: (admin: AdminUserView) => apiDelete<void>(`/api/v1/admin/admins/${admin.id}`),
    onSuccess: () => {
      toast({ variant: "success", title: "운영자가 삭제되었습니다." });
      qc.invalidateQueries({ queryKey: ["admins"] });
      setDeleteTarget(null);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const all = data?.content ?? [];
  const total = data?.totalElements ?? all.length;
  const platformCount = all.filter((u) => u.role === "PLATFORM_OPERATOR").length;
  const rpCount = all.filter((u) => u.role === "RP_ADMIN").length;

  return (
    <>
      <PageHeader
        title="운영자 관리"
        description="플랫폼 운영자 / RP 관리자 계정을 생성하고 비밀번호를 재설정합니다."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1.5 h-3.5 w-3.5" /> 신규 운영자
          </Button>
        }
      />

      <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <MetricCard
          label="총 운영자"
          value={isLoading ? "…" : total}
          sub={`현재 페이지 ${all.length}명`}
        />
        <MetricCard
          label="Platform Operator"
          value={isLoading ? "…" : platformCount}
          sub="cross-tenant 권한"
        />
        <MetricCard
          label="RP Admin"
          value={isLoading ? "…" : rpCount}
          sub="tenant-scoped 권한"
        />
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">불러오는 중…</p>
      ) : all.length === 0 ? (
        <EmptyState title="등록된 운영자가 없습니다." />
      ) : (
        <div
          className="overflow-hidden rounded-lg border"
          style={{
            background: "var(--surface)",
            borderColor: "var(--border-subtle)",
            boxShadow: "var(--shadow-xs)",
          }}
        >
          <div
            className="flex items-center justify-between px-5 py-3"
            style={{ borderBottom: "1px solid var(--border-subtle)" }}
          >
            <div>
              <h3 className="text-[14px] font-semibold tracking-tight">
                콘솔 운영자
              </h3>
              <p
                className="mt-0.5 text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                {total}명 · Platform {platformCount} · RP {rpCount}
              </p>
            </div>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>운영자</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Tenant</TableHead>
                <TableHead>마지막 로그인</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-40 text-right">액션</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {all.map((u) => {
                const self = me?.adminId === u.id;
                const isPlatform = u.role === "PLATFORM_OPERATOR";
                const initial =
                  u.displayName.trim().slice(0, 1).toUpperCase() || "?";
                return (
                  <TableRow key={u.id}>
                    <TableCell>
                      <div className="flex items-center gap-2.5">
                        <div
                          className="grid h-7 w-7 shrink-0 place-items-center rounded-full text-[11px] font-bold"
                          style={{
                            background: isPlatform
                              ? "var(--violet-soft)"
                              : "var(--info-soft)",
                            color: isPlatform
                              ? "var(--violet)"
                              : "var(--info)",
                          }}
                        >
                          {initial}
                        </div>
                        <div className="min-w-0">
                          <div className="text-[13px] font-semibold">
                            {u.displayName}
                          </div>
                          <div
                            className="font-mono text-[11px]"
                            style={{ color: "var(--text-mute)" }}
                          >
                            {u.email}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={isPlatform ? "violet" : "info"}>
                        {u.role}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-[12px]">
                      {u.tenantId ? (
                        lastN(u.tenantId, 10)
                      ) : (
                        <span style={{ color: "var(--text-faint)" }}>—</span>
                      )}
                    </TableCell>
                    <TableCell
                      className="text-[12px]"
                      style={{ color: "var(--text-mute)" }}
                    >
                      {u.lastLoginAt ? (
                        formatDateTime(u.lastLoginAt)
                      ) : (
                        <span style={{ color: "var(--text-faint)" }}>
                          미접속
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          u.status === "ACTIVE" ? "success" : "destructive"
                        }
                        className="gap-1"
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: "currentColor" }}
                        />
                        {u.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="space-x-1 text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={self}
                        onClick={() => setResetTarget(u)}
                      >
                        <KeyRound className="mr-1 h-3.5 w-3.5" /> 비밀번호
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={self}
                        onClick={() => setDeleteTarget(u)}
                      >
                        <Trash2 className="mr-1 h-3.5 w-3.5" /> 삭제
                      </Button>
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
              page {data ? data.page + 1 : 1} of {data?.totalPages ?? 1} · 총 {total}명
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

      <CreateAdminDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(result) => {
          setCreateOpen(false);
          setIssued(result);
          qc.invalidateQueries({ queryKey: ["admins"] });
        }}
      />
      <TempPasswordModal
        issued={issued ?? resetIssued}
        onClose={() => {
          setIssued(null);
          setResetIssued(null);
        }}
      />
      <ConfirmResetDialog
        target={resetTarget}
        onCancel={() => setResetTarget(null)}
        onConfirm={() => resetTarget && reset.mutate(resetTarget)}
        pending={reset.isPending}
      />
      <ConfirmDeleteDialog
        target={deleteTarget}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && remove.mutate(deleteTarget)}
        pending={remove.isPending}
      />
    </>
  );
}

const createSchema = z
  .object({
    email: z.string().email("이메일 형식이 올바르지 않습니다"),
    displayName: z.string().min(1, "이름을 입력하세요"),
    role: z.enum(["PLATFORM_OPERATOR", "RP_ADMIN"]),
    tenantId: z.string().uuid().optional().or(z.literal("")),
  })
  .refine((d) => d.role !== "RP_ADMIN" || (d.tenantId && d.tenantId.length > 0), {
    message: "RP_ADMIN은 tenantId가 필요합니다",
    path: ["tenantId"],
  });

type CreateForm = z.infer<typeof createSchema>;

function CreateAdminDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (result: CreatedAdminView) => void;
}) {
  const { toast } = useToast();
  const {
    register,
    handleSubmit,
    reset: resetForm,
    setValue,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<CreateForm>({
    resolver: zodResolver(createSchema),
    defaultValues: { role: "PLATFORM_OPERATOR" },
  });
  const role = watch("role");

  React.useEffect(() => {
    if (!open) resetForm({ role: "PLATFORM_OPERATOR" });
  }, [open, resetForm]);

  const create = useMutation({
    mutationFn: (req: CreateAdminRequest) =>
      apiPost<CreatedAdminView>("/api/v1/admin/admins", req),
    onSuccess: onCreated,
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>신규 운영자 생성</DialogTitle>
          <DialogDescription>
            발급 직후 임시 비밀번호가 1회만 노출됩니다. 안전하게 전달하세요.
          </DialogDescription>
        </DialogHeader>
        <form
          id="create-admin-form"
          onSubmit={handleSubmit((d) =>
            create.mutate({
              email: d.email,
              displayName: d.displayName,
              role: d.role as AdminRole,
              tenantId: d.role === "RP_ADMIN" ? d.tenantId || undefined : undefined,
            }),
          )}
          className="space-y-3"
        >
          <div className="space-y-1.5">
            <Label htmlFor="email">이메일</Label>
            <Input id="email" autoFocus {...register("email")} />
            {errors.email && (
              <p className="text-xs text-destructive">{errors.email.message}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="displayName">이름</Label>
            <Input id="displayName" {...register("displayName")} />
            {errors.displayName && (
              <p className="text-xs text-destructive">{errors.displayName.message}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="role">Role</Label>
            <Select value={role} onValueChange={(v) => setValue("role", v as AdminRole)}>
              <SelectTrigger id="role">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="PLATFORM_OPERATOR">PLATFORM_OPERATOR</SelectItem>
                <SelectItem value="RP_ADMIN">RP_ADMIN</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {role === "RP_ADMIN" && (
            <div className="space-y-1.5">
              <Label htmlFor="tenantId">Tenant ID</Label>
              <Input id="tenantId" placeholder="UUID" {...register("tenantId")} />
              {errors.tenantId && (
                <p className="text-xs text-destructive">{errors.tenantId.message}</p>
              )}
            </div>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button
            type="submit"
            form="create-admin-form"
            disabled={isSubmitting || create.isPending}
          >
            {create.isPending ? "생성 중…" : "생성"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TempPasswordModal({
  issued,
  onClose,
}: {
  issued: { admin: AdminUserView; temporaryPassword: string } | null;
  onClose: () => void;
}) {
  const [confirmed, setConfirmed] = React.useState(false);
  React.useEffect(() => {
    if (!issued) setConfirmed(false);
  }, [issued]);

  return (
    <Dialog
      open={!!issued}
      onOpenChange={(open) => {
        if (!open && confirmed) onClose();
      }}
    >
      <DialogContent
        hideCloseButton
        onEscapeKeyDown={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>⚠️ 임시 비밀번호가 발급되었습니다</DialogTitle>
          <DialogDescription>
            <strong>지금만</strong> 표시됩니다. 안전하게 전달 후 사용자가 첫 로그인 시 즉시 비밀번호를
            변경하도록 안내하세요.
          </DialogDescription>
        </DialogHeader>
        {issued && (
          <div className="space-y-3">
            <div className="rounded-md border bg-muted/40 p-3">
              <p className="text-xs text-muted-foreground">
                {issued.admin.email} · {issued.admin.role}
              </p>
              <p className="mt-1 break-all font-mono text-sm">{issued.temporaryPassword}</p>
              <div className="mt-2 flex justify-end">
                <CopyButton value={issued.temporaryPassword} />
              </div>
            </div>
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <Checkbox checked={confirmed} onCheckedChange={(v) => setConfirmed(!!v)} />
              안전한 경로로 전달하거나 기록했습니다.
            </label>
          </div>
        )}
        <DialogFooter>
          <Button disabled={!confirmed} onClick={onClose}>
            닫기
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ConfirmResetDialog({
  target,
  onCancel,
  onConfirm,
  pending,
}: {
  target: AdminUserView | null;
  onCancel: () => void;
  onConfirm: () => void;
  pending: boolean;
}) {
  return (
    <Dialog open={!!target} onOpenChange={(open) => !open && onCancel()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>비밀번호 재설정</DialogTitle>
          <DialogDescription>
            새 임시 비밀번호가 발급되며 기존 비밀번호는 즉시 무효화됩니다.
          </DialogDescription>
        </DialogHeader>
        {target && (
          <div className="rounded-md border bg-muted/40 p-3 text-sm">
            <p>
              <span className="text-muted-foreground">Email:</span> {target.email}
            </p>
            <p>
              <span className="text-muted-foreground">Role:</span> {target.role}
            </p>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            취소
          </Button>
          <Button variant="destructive" onClick={onConfirm} disabled={pending}>
            {pending ? "처리 중…" : "재설정"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ConfirmDeleteDialog({
  target,
  onCancel,
  onConfirm,
  pending,
}: {
  target: AdminUserView | null;
  onCancel: () => void;
  onConfirm: () => void;
  pending: boolean;
}) {
  return (
    <Dialog open={!!target} onOpenChange={(open) => !open && onCancel()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>운영자 삭제</DialogTitle>
          <DialogDescription>
            이 작업은 되돌릴 수 없습니다. 해당 운영자는 즉시 로그인 불가가 됩니다.
          </DialogDescription>
        </DialogHeader>
        {target && (
          <div className="rounded-md border bg-muted/40 p-3 text-sm">
            <p>
              <span className="text-muted-foreground">Email:</span> {target.email}
            </p>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            취소
          </Button>
          <Button variant="destructive" onClick={onConfirm} disabled={pending}>
            {pending ? "처리 중…" : "삭제"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
