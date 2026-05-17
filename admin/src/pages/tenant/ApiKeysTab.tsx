import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  AlertTriangle,
  Check,
  Copy,
  Info,
  Key,
  Lock,
  Plus,
  Trash2,
} from "lucide-react";
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
import { apiDelete, apiGet, apiPost, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/cn";
import type {
  ApiKeyView,
  IssueApiKeyRequest,
  IssuedKeyView,
} from "@/types/api";

const ROTATION_DAYS = 90;

const nameSchema = z.object({
  name: z
    .string()
    .min(1, "이름을 입력하세요")
    .max(100)
    .regex(/^[\x20-\x7E]+$/, "ASCII printable 문자만 사용"),
});

export function ApiKeysTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ["apiKeys", tenantId],
    queryFn: () =>
      apiGet<ApiKeyView[]>(`/api/v1/admin/tenants/${tenantId}/api-keys`),
    enabled: !!tenantId,
  });

  const [issueOpen, setIssueOpen] = React.useState(false);
  const [issued, setIssued] = React.useState<IssuedKeyView | null>(null);
  const [revokeTarget, setRevokeTarget] = React.useState<ApiKeyView | null>(
    null,
  );

  const issue = useMutation({
    mutationFn: (body: IssueApiKeyRequest) =>
      apiPost<IssuedKeyView>(
        `/api/v1/admin/tenants/${tenantId}/api-keys`,
        body,
      ),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["apiKeys", tenantId] });
      setIssueOpen(false);
      setIssued(result);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const revoke = useMutation({
    mutationFn: (keyId: string) =>
      apiDelete<void>(`/api/v1/admin/tenants/${tenantId}/api-keys/${keyId}`),
    onSuccess: async () => {
      // Await the refetch so the table reflects the REVOKED row before the dialog tears down —
      // otherwise the user can see a momentary stale ACTIVE state while the cache cycles.
      await qc.invalidateQueries({ queryKey: ["apiKeys", tenantId] });
      toast({ variant: "success", title: "API key가 회수되었습니다." });
      setRevokeTarget(null);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const all = data ?? [];
  const activeCount = all.filter((k) => k.status === "ACTIVE").length;
  const revokedCount = all.length - activeCount;
  const latest = all
    .slice()
    .sort((a, b) => +new Date(b.createdAt) - +new Date(a.createdAt))[0];
  const nextRotationDays = latest
    ? Math.max(
        0,
        Math.round(
          ROTATION_DAYS -
            (Date.now() - new Date(latest.createdAt).getTime()) / 86_400_000,
        ),
      )
    : null;

  return (
    <div className="space-y-4">
      <PageHeader
        title="API Keys"
        description="RP 백엔드가 platform API 호출에 사용하는 키입니다. plaintext는 발급 직후 1회만 노출됩니다."
        actions={
          <Button onClick={() => setIssueOpen(true)}>
            <Plus className="mr-1.5 h-3.5 w-3.5" /> 새 키 발급
          </Button>
        }
      />

      {/* Metric strip */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <MetricCard
          label="총 API Key"
          value={isLoading ? "…" : all.length}
          sub={`활성 ${activeCount} · 회수 ${revokedCount}`}
        />
        <MetricCard
          label="최근 발급"
          value={
            latest
              ? `${Math.max(
                  0,
                  Math.floor(
                    (Date.now() - new Date(latest.createdAt).getTime()) /
                      86_400_000,
                  ),
                )}일 전`
              : "—"
          }
          sub={latest ? `${latest.name} · ${latest.prefix}` : "발급 없음"}
        />
        <MetricCard
          label="권장 rotation"
          value={`${ROTATION_DAYS}일`}
          sub={
            nextRotationDays !== null
              ? `다음 키 회전: ${nextRotationDays}일 후`
              : "—"
          }
        />
      </div>

      {/* Table card */}
      {isLoading ? (
        <p className="text-sm text-muted-foreground">불러오는 중…</p>
      ) : all.length === 0 ? (
        <EmptyState title="아직 발급된 API key가 없습니다." />
      ) : (
        <div
          className="overflow-hidden rounded-lg border"
          style={{
            background: "var(--surface)",
            borderColor: "var(--border-subtle)",
            boxShadow: "var(--shadow-xs)",
          }}
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Prefix</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>마지막 사용</TableHead>
                <TableHead>생성</TableHead>
                <TableHead className="w-24 text-right">액션</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {all.map((k) => {
                const revoked = k.status === "REVOKED";
                return (
                  <TableRow
                    key={k.id}
                    className={cn(revoked && "opacity-60")}
                  >
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <Key
                          className="h-3.5 w-3.5"
                          style={{ color: "var(--text-mute)" }}
                        />
                        <span className="font-mono text-[12px] font-semibold">
                          {k.prefix}
                          <span style={{ color: "var(--text-faint)" }}>
                            .•••••
                          </span>
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>{k.name}</TableCell>
                    <TableCell>
                      <Badge
                        variant={revoked ? "default" : "success"}
                        className="gap-1"
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: "currentColor" }}
                        />
                        {k.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-[12px]">
                      <LastUsedCell value={k.lastUsedAt} />
                    </TableCell>
                    <TableCell
                      className="text-[12px]"
                      style={{ color: "var(--text-mute)" }}
                    >
                      {formatDateTime(k.createdAt)}
                    </TableCell>
                    <TableCell className="text-right">
                      {!revoked && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRevokeTarget(k)}
                          className="border-danger/30 text-danger hover:bg-danger/10 hover:text-danger"
                          style={{
                            borderColor:
                              "color-mix(in oklab, var(--danger) 30%, var(--border))",
                            color: "var(--danger)",
                          }}
                        >
                          <Trash2 className="mr-1 h-3.5 w-3.5" /> 회수
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}

      <IssueDialog
        open={issueOpen}
        onOpenChange={setIssueOpen}
        onSubmit={(data) => issue.mutate(data)}
        pending={issue.isPending}
      />
      <IssuedKeyModal issued={issued} onClose={() => setIssued(null)} />
      <RevokeDialog
        target={revokeTarget}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
        onConfirm={() => revokeTarget && revoke.mutate(revokeTarget.id)}
        pending={revoke.isPending}
      />
    </div>
  );
}

function LastUsedCell({ value }: { value: string | null }) {
  if (!value) {
    return <span style={{ color: "var(--text-faint)" }}>미사용</span>;
  }
  const ageDays = (Date.now() - new Date(value).getTime()) / 86_400_000;
  const stale = ageDays >= 30;
  return (
    <div className="flex items-center gap-2">
      <span style={{ color: "var(--text-mute)" }}>{formatDateTime(value)}</span>
      {stale && <Badge variant="warning">stale</Badge>}
    </div>
  );
}

function IssueDialog({
  open,
  onOpenChange,
  onSubmit,
  pending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: IssueApiKeyRequest) => void;
  pending: boolean;
}) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<IssueApiKeyRequest>({ resolver: zodResolver(nameSchema) });

  React.useEffect(() => {
    if (!open) reset();
  }, [open, reset]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>새 API key 발급</DialogTitle>
          <DialogDescription>
            발급 후 plaintext는 단 한 번만 노출됩니다. 안전한 장소에 즉시 보관하세요.
          </DialogDescription>
        </DialogHeader>
        <form
          id="issue-key-form"
          onSubmit={handleSubmit(onSubmit)}
          className="space-y-2"
        >
          <Label htmlFor="key-name" className="text-[12px] font-semibold">
            용도 (이름)
          </Label>
          <Input
            id="key-name"
            autoFocus
            placeholder="production"
            {...register("name")}
          />
          <p
            className="text-[12px]"
            style={{ color: "var(--text-mute)" }}
          >
            배포 환경이나 용도를 짧게. 예: production, staging, mobile-app
          </p>
          {errors.name && (
            <p className="text-xs text-destructive">{errors.name.message}</p>
          )}
        </form>
        <div
          className="flex gap-2 rounded-md px-3 py-2.5 text-[12px]"
          style={{ background: "var(--info-soft)", color: "var(--info)" }}
        >
          <Info className="mt-px h-3.5 w-3.5 shrink-0" />
          <span>
            발급된 key는 Crosscert이 평문을 보관하지 않습니다. 분실 시 회수 후 재발급만 가능합니다.
          </span>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button type="submit" form="issue-key-form" disabled={pending}>
            {pending ? "발급 중…" : "발급"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function IssuedKeyModal({
  issued,
  onClose,
}: {
  issued: IssuedKeyView | null;
  onClose: () => void;
}) {
  const [confirmed, setConfirmed] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  React.useEffect(() => {
    if (!issued) {
      setConfirmed(false);
      setCopied(false);
    }
  }, [issued]);

  if (!issued) return null;

  // Split prefix from the rest of the plaintext so we can accent the prefix.
  const tail = issued.plaintext.startsWith(`${issued.prefix}.`)
    ? issued.plaintext.slice(issued.prefix.length + 1)
    : issued.plaintext;

  function copy() {
    navigator.clipboard?.writeText(issued!.plaintext);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && confirmed) onClose();
      }}
    >
      <DialogContent
        className="sm:max-w-[720px]"
        hideCloseButton
        onEscapeKeyDown={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            새 API key가 발급되었습니다 — 지금만 표시됩니다
          </DialogTitle>
          <DialogDescription>
            이 창을 닫으면 plaintext는 영구히 사라집니다. 절대 다시 표시되지 않습니다.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="flex flex-wrap items-start gap-3">
            <Badge variant="success">발급 완료</Badge>
            <div className="min-w-0 flex-1">
              <div
                className="text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                이름
              </div>
              <div className="text-[14px] font-semibold">{issued.name}</div>
            </div>
            <div>
              <div
                className="text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                prefix
              </div>
              <div className="font-mono text-[12px]">{issued.prefix}</div>
            </div>
            <div>
              <div
                className="text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                id
              </div>
              <div className="font-mono text-[12px]">{issued.id}</div>
            </div>
          </div>

          <div>
            <Label className="text-[12px] font-semibold">
              plaintext API key
            </Label>
            <div className="relative mt-1.5">
              <div
                className="break-all rounded-md border p-3.5 pr-24 font-mono text-[12px] leading-relaxed"
                style={{
                  background: "var(--surface-3)",
                  borderColor: "var(--border)",
                  color: "var(--text)",
                }}
              >
                <span
                  style={{ color: "var(--accent)", fontWeight: 600 }}
                >
                  {issued.prefix}
                </span>
                .{tail}
              </div>
              <Button
                size="sm"
                className="absolute right-2 top-2"
                onClick={copy}
              >
                {copied ? (
                  <>
                    <Check className="mr-1 h-3.5 w-3.5" /> 복사됨
                  </>
                ) : (
                  <>
                    <Copy className="mr-1 h-3.5 w-3.5" /> 클립보드
                  </>
                )}
              </Button>
            </div>
          </div>

          <label
            className="flex cursor-pointer items-start gap-2.5 rounded-md border p-3 text-[13px]"
            style={{
              background: confirmed
                ? "var(--success-soft)"
                : "var(--warning-soft)",
              borderColor: confirmed
                ? "color-mix(in oklab, var(--success) 25%, transparent)"
                : "color-mix(in oklab, var(--warning) 25%, transparent)",
            }}
          >
            <Checkbox
              checked={confirmed}
              onCheckedChange={(v) => setConfirmed(!!v)}
              className="mt-0.5"
            />
            <div>
              <div
                className="font-semibold"
                style={{
                  color: confirmed ? "var(--success)" : "var(--warning)",
                }}
              >
                안전한 장소에 복사했습니다.
              </div>
              <div
                className="mt-0.5 text-[12px]"
                style={{ color: "var(--text-soft)" }}
              >
                1Password, AWS Secrets Manager 등 보안 저장소에 보관하세요. 닫기 후에는 재조회 불가능합니다.
              </div>
            </div>
          </label>
        </div>

        <DialogFooter>
          <div
            className="flex flex-1 items-center gap-2 text-[12px]"
            style={{ color: "var(--text-mute)" }}
          >
            <Lock className="h-3 w-3" />
            server는 plaintext의 해시만 저장합니다.
          </div>
          <Button disabled={!confirmed} onClick={onClose}>
            {confirmed ? "닫기 (영구 소실)" : "체크 필요"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RevokeDialog({
  target,
  onOpenChange,
  onConfirm,
  pending,
}: {
  target: ApiKeyView | null;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  pending: boolean;
}) {
  return (
    <Dialog open={!!target} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>API key를 회수하시겠습니까?</DialogTitle>
          <DialogDescription>
            회수된 키는 다음 ceremony부터 401을 받습니다. 캐시 만료까지 약 5초 이내에 완전 차단됩니다.
          </DialogDescription>
        </DialogHeader>
        {target && (
          <div
            className="rounded-md border p-3.5"
            style={{
              background: "var(--surface-2)",
              borderColor: "var(--border)",
            }}
          >
            <div
              className="grid items-center gap-y-2 text-[13px]"
              style={{ gridTemplateColumns: "100px 1fr" }}
            >
              <div style={{ color: "var(--text-mute)" }}>prefix</div>
              <div className="font-mono">{target.prefix}</div>
              <div style={{ color: "var(--text-mute)" }}>이름</div>
              <div>{target.name}</div>
              <div style={{ color: "var(--text-mute)" }}>생성</div>
              <div style={{ color: "var(--text-mute)" }}>
                {formatDateTime(target.createdAt)}
              </div>
            </div>
          </div>
        )}
        <div
          className="flex gap-2 rounded-md px-3 py-2.5 text-[12px]"
          style={{ background: "var(--danger-soft)", color: "var(--danger)" }}
        >
          <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
          <span>
            이 작업은 되돌릴 수 없습니다. RP 서비스에 새 키가 배포되어 있는지 확인하세요.
          </span>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button variant="destructive" onClick={onConfirm} disabled={pending}>
            {pending ? "회수 중…" : "회수"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
