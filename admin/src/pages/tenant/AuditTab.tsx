import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Download, Hash } from "lucide-react";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
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
import { apiGet, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { formatDateTime, lastN } from "@/lib/format";
import { cn } from "@/lib/cn";
import {
  AUDIT_EVENT_TYPES,
  type AuditEventType,
  type AuditView,
  type ChainVerification,
  type PageResponse,
} from "@/types/api";

export function AuditTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const [page, setPage] = React.useState(0);
  const size = 50;
  const [eventFilter, setEventFilter] = React.useState<"ALL" | AuditEventType>("ALL");
  const [openPayload, setOpenPayload] = React.useState<AuditView | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["audit", tenantId, { page, size, eventFilter }],
    queryFn: () => {
      const filterParam = eventFilter === "ALL" ? "" : `&eventType=${eventFilter}`;
      return apiGet<PageResponse<AuditView>>(
        `/api/v1/admin/tenants/${tenantId}/audit-logs?page=${page}&size=${size}${filterParam}`,
      );
    },
    enabled: !!tenantId,
  });

  React.useEffect(() => {
    setPage(0);
  }, [eventFilter]);
  const filtered = data?.content ?? [];

  const [verification, setVerification] = React.useState<ChainVerification | null>(
    null,
  );
  const tamperedSet = React.useMemo(
    () => new Set(verification?.tamperedEntryIds ?? []),
    [verification],
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="Audit Log"
        description="Tenant 활동 기록. Hash chain 무결성도 이 페이지에서 검증합니다."
      />

      <ChainVerifyCard
        tenantId={tenantId!}
        onResult={setVerification}
        result={verification}
      />

      {/* Filter + table card */}
      <div
        className="overflow-hidden rounded-lg border"
        style={{
          background: "var(--surface)",
          borderColor: "var(--border-subtle)",
          boxShadow: "var(--shadow-xs)",
        }}
      >
        <div
          className="flex flex-wrap items-center justify-between gap-3 px-5 py-3"
          style={{ borderBottom: "1px solid var(--border-subtle)" }}
        >
          <div className="flex items-center gap-2">
            <Label htmlFor="evt-filter" className="text-[12px]" style={{ color: "var(--text-mute)" }}>
              Event
            </Label>
            <Select
              value={eventFilter}
              onValueChange={(v) => setEventFilter(v as "ALL" | AuditEventType)}
            >
              <SelectTrigger id="evt-filter" className="h-8 w-64 text-[12px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">전체</SelectItem>
                {AUDIT_EVENT_TYPES.map((e) => (
                  <SelectItem key={e} value={e}>
                    {e}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {data && (
              <span
                className="text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                {data.totalElements}건
              </span>
            )}
          </div>
        </div>

        {isLoading ? (
          <p className="p-4 text-sm text-muted-foreground">불러오는 중…</p>
        ) : filtered.length === 0 ? (
          <EmptyState title="아직 활동 기록이 없습니다." />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>시각</TableHead>
                  <TableHead>eventType</TableHead>
                  <TableHead>actor</TableHead>
                  <TableHead>subject</TableHead>
                  <TableHead>payload</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((row) => (
                  <TableRow
                    key={row.id}
                    className={cn(
                      "cursor-pointer",
                      tamperedSet.has(row.id) && "bg-destructive/5",
                    )}
                    onClick={() => setOpenPayload(row)}
                  >
                    <TableCell className="whitespace-nowrap">
                      <div className="flex flex-col">
                        <span
                          className="text-[12px] font-medium"
                          style={{ color: "var(--text)" }}
                        >
                          {formatDateTime(row.createdAt)}
                        </span>
                        <span
                          className="text-[11px]"
                          style={{ color: "var(--text-faint)" }}
                        >
                          {timeAgo(row.createdAt)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={badgeVariantFor(row.eventType)}
                        className="gap-1 font-mono text-[10px]"
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: "currentColor" }}
                        />
                        {row.eventType}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <Badge variant="default" className="w-fit text-[10px]">
                          {row.actorType}
                        </Badge>
                        <span
                          className="font-mono text-[11px]"
                          style={{ color: "var(--text-faint)" }}
                        >
                          {lastN(row.actorId ?? "—", 10)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <Badge variant="default" className="w-fit text-[10px]">
                          {row.subjectType ?? "—"}
                        </Badge>
                        <span
                          className="font-mono text-[11px]"
                          style={{ color: "var(--text-faint)" }}
                        >
                          {lastN(row.subjectId ?? "—", 12)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <code
                        className="block max-w-[360px] truncate text-[11px]"
                        style={{ color: "var(--text-soft)" }}
                      >
                        {previewPayload(row.payload)}
                      </code>
                    </TableCell>
                  </TableRow>
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
                page {data ? data.page + 1 : 1} of {data?.totalPages ?? 1} · 페이지당 {size}건
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
          </>
        )}
      </div>

      <PayloadModal
        event={openPayload}
        onOpenChange={(open) => !open && setOpenPayload(null)}
      />
    </div>
  );
}

function previewPayload(raw: string): string {
  if (!raw) return "—";
  const flat = raw.replace(/\s+/g, " ");
  return flat.length > 80 ? `${flat.slice(0, 80)}…` : flat;
}

// Hoisted to module scope (js-cache-function-results) — this lookup table is static, so
// rebuilding it on every row render was pure waste in a 50-row table.
const EVENT_BADGE_VARIANT: Partial<Record<AuditEventType, BadgeProps["variant"]>> = {
  CREDENTIAL_AUTHENTICATED: "success",
  CREDENTIAL_REGISTERED: "info",
  CREDENTIAL_REVOKED: "destructive",
  API_KEY_ISSUED: "violet",
  API_KEY_REVOKED: "destructive",
  WEBAUTHN_CONFIG_UPDATED: "warning",
  SIGNATURE_COUNTER_REGRESSION: "destructive",
  ATTESTATION_TRUST_FAILED: "destructive",
  TENANT_CREATED: "success",
};

function badgeVariantFor(e: AuditEventType): BadgeProps["variant"] {
  return EVENT_BADGE_VARIANT[e] ?? "default";
}

function timeAgo(iso: string) {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const diff = Math.max(0, (Date.now() - t) / 1000);
  if (diff < 60) return diff < 2 ? "방금" : `${Math.floor(diff)}초 전`;
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}일 전`;
  return new Date(iso).toLocaleDateString("ko-KR");
}

function PayloadModal({
  event,
  onOpenChange,
}: {
  event: AuditView | null;
  onOpenChange: (open: boolean) => void;
}) {
  const pretty = React.useMemo(() => {
    if (!event?.payload) return "";
    try {
      return JSON.stringify(JSON.parse(event.payload), null, 2);
    } catch {
      return event.payload;
    }
  }, [event]);
  if (!event) {
    return (
      <Dialog open={false} onOpenChange={onOpenChange}>
        <DialogContent />
      </Dialog>
    );
  }
  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[720px]">
        <DialogHeader>
          <DialogTitle>Audit Event</DialogTitle>
          <p
            className="text-[12px]"
            style={{ color: "var(--text-mute)" }}
          >
            {formatDateTime(event.createdAt)}
          </p>
        </DialogHeader>
        <div
          className="grid items-center gap-y-2.5 text-[13px]"
          style={{ gridTemplateColumns: "130px 1fr" }}
        >
          <div style={{ color: "var(--text-mute)" }}>eventType</div>
          <div>
            <Badge
              variant={badgeVariantFor(event.eventType)}
              className="gap-1 font-mono text-[10px]"
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ background: "currentColor" }}
              />
              {event.eventType}
            </Badge>
          </div>
          <div style={{ color: "var(--text-mute)" }}>actor</div>
          <div className="flex items-center gap-2">
            <Badge variant="default" className="text-[10px]">
              {event.actorType}
            </Badge>
            <span className="font-mono text-[12px]">
              {event.actorId ?? "—"}
            </span>
          </div>
          <div style={{ color: "var(--text-mute)" }}>subject</div>
          <div className="flex items-center gap-2">
            <Badge variant="default" className="text-[10px]">
              {event.subjectType ?? "—"}
            </Badge>
            <span className="font-mono text-[12px]">
              {event.subjectId ?? "—"}
            </span>
          </div>
        </div>
        <Label className="text-[12px] font-semibold">payload</Label>
        <pre
          className="max-h-[40vh] overflow-auto rounded-md p-3.5 font-mono text-[12px]"
          style={{
            background: "var(--surface-3)",
            color: "var(--text)",
          }}
        >
          {pretty}
        </pre>
      </DialogContent>
    </Dialog>
  );
}

function ChainVerifyCard({
  tenantId,
  result,
  onResult,
}: {
  tenantId: string;
  result: ChainVerification | null;
  onResult: (r: ChainVerification | null) => void;
}) {
  const { toast } = useToast();
  const now = React.useMemo(() => new Date(), []);
  const yesterday = React.useMemo(() => {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - 1);
    d.setUTCHours(0, 0, 0, 0);
    return d;
  }, [now]);
  const [from, setFrom] = React.useState(toLocalInput(yesterday));
  const [to, setTo] = React.useState(toLocalInput(now));
  const [open, setOpen] = React.useState(false);

  const verify = useMutation({
    mutationFn: async () => {
      const fromIso = new Date(from).toISOString();
      const toIso = new Date(to).toISOString();
      return apiGet<ChainVerification>(
        `/api/v1/admin/tenants/${tenantId}/audit-logs/verify?from=${encodeURIComponent(
          fromIso,
        )}&to=${encodeURIComponent(toIso)}`,
      );
    },
    onSuccess: (r) => {
      onResult(r);
      setOpen(false);
      toast({
        variant: r.tamperedEntryIds.length === 0 ? "success" : "destructive",
        title:
          r.tamperedEntryIds.length === 0
            ? `무결 · ${r.verifiedRows.toLocaleString()}건 검증`
            : `위변조 의심 ${r.tamperedEntryIds.length}건`,
      });
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const intact = result && result.tamperedEntryIds.length === 0;

  return (
    <>
      <div
        className="rounded-lg border"
        style={{
          background: "var(--surface)",
          borderColor: "var(--border-subtle)",
          boxShadow: "var(--shadow-xs)",
        }}
      >
        <div className="flex flex-wrap items-center gap-3.5 p-5">
          <div
            className="grid h-10 w-10 shrink-0 place-items-center rounded-lg"
            style={{ background: "var(--accent-soft)", color: "var(--accent)" }}
          >
            <Hash className="h-5 w-5" />
          </div>
          <div className="flex-1">
            <div className="text-[14px] font-semibold">
              Audit Hash Chain 검증
            </div>
            <div
              className="mt-0.5 text-[12px]"
              style={{ color: "var(--text-mute)" }}
            >
              기간 내 모든 audit row의 prevHash → SHA-256 chain을 재계산하여 변조 여부를 확인합니다.
            </div>
          </div>
          {result && (
            <div className="flex items-center gap-3">
              <div className="flex flex-col items-end">
                <span
                  className="text-[11px]"
                  style={{ color: "var(--text-mute)" }}
                >
                  verifiedRows
                </span>
                <span className="font-mono text-[13px] font-semibold tabular-nums">
                  {result.verifiedRows.toLocaleString()}
                </span>
              </div>
              {intact ? (
                <Badge variant="success" className="gap-1 px-2.5">
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: "currentColor" }}
                  />
                  INTACT
                </Badge>
              ) : (
                <Badge variant="destructive" className="gap-1 px-2.5">
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: "currentColor" }}
                  />
                  위변조 {result.tamperedEntryIds.length}건
                </Badge>
              )}
            </div>
          )}
          <Button size="sm" onClick={() => setOpen(true)}>
            <Hash className="mr-1 h-3.5 w-3.5" /> 검증 실행
          </Button>
          {result && intact && (
            <Button size="sm" variant="outline" disabled>
              <Download className="mr-1 h-3.5 w-3.5" /> 보고서
            </Button>
          )}
        </div>
        {result && result.tamperedEntryIds.length > 0 && (
          <div
            className="border-t p-4 text-[12px]"
            style={{
              background: "var(--danger-soft)",
              borderColor:
                "color-mix(in oklab, var(--danger) 25%, var(--border))",
            }}
          >
            <p className="font-semibold" style={{ color: "var(--danger)" }}>
              위변조 의심 entry ID
            </p>
            <ul className="mt-1 list-disc pl-5 font-mono">
              {result.tamperedEntryIds.map((id) => (
                <li key={id}>{id}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-[640px]">
          <DialogHeader>
            <DialogTitle>Hash chain 검증</DialogTitle>
            <p className="text-[12px]" style={{ color: "var(--text-mute)" }}>
              대상 기간 안에 있는 audit row를 chain으로 재계산합니다.
            </p>
          </DialogHeader>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="from" className="text-[12px] font-semibold">
                from
              </Label>
              <Input
                id="from"
                type="datetime-local"
                className="font-mono"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="to" className="text-[12px] font-semibold">
                to
              </Label>
              <Input
                id="to"
                type="datetime-local"
                className="font-mono"
                value={to}
                onChange={(e) => setTo(e.target.value)}
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={verify.isPending}
            >
              취소
            </Button>
            <Button
              onClick={() => verify.mutate()}
              disabled={verify.isPending}
            >
              {verify.isPending ? "검증 중…" : "검증 실행"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function toLocalInput(date: Date): string {
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
