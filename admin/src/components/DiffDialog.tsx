import * as React from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export interface DiffChange {
  key: string;
  from: unknown;
  to: unknown;
}

export function diffObjects<T extends Record<string, unknown>>(a: T, b: T): DiffChange[] {
  const out: DiffChange[] = [];
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  keys.forEach((k) => {
    if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) {
      out.push({ key: k, from: a[k], to: b[k] });
    }
  });
  return out;
}

export function DiffDialog({
  open,
  onOpenChange,
  changes,
  onConfirm,
  busy,
  title = "변경 사항 확인",
  description = "저장하면 다음 ceremony부터 라이브 RP에 즉시 적용됩니다.",
  auditEventType,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  changes: DiffChange[];
  onConfirm: () => void;
  busy?: boolean;
  title?: React.ReactNode;
  description?: React.ReactNode;
  auditEventType?: string;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <div
          className="overflow-hidden rounded-md border"
          style={{ borderColor: "var(--border)" }}
        >
          {changes.length === 0 ? (
            <div
              className="p-4 text-[13px]"
              style={{ color: "var(--text-mute)" }}
            >
              변경 사항이 없습니다.
            </div>
          ) : (
            changes.map((c, i) => (
              <DiffRow
                key={c.key}
                c={c}
                last={i === changes.length - 1}
              />
            ))
          )}
        </div>

        {auditEventType && changes.length > 0 && (
          <div
            className="mt-3 flex gap-2 rounded-md px-3 py-2.5 text-[12px]"
            style={{ background: "var(--warning-soft)", color: "var(--warning)" }}
          >
            <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
            <span>
              이 변경은 즉시 라이브 RP에 영향을 줍니다. audit log에{" "}
              <code
                className="rounded px-1"
                style={{ background: "rgba(0,0,0,0.05)" }}
              >
                {auditEventType}
              </code>
              으로 기록됩니다.
            </span>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button
            disabled={busy || changes.length === 0}
            onClick={onConfirm}
          >
            {busy ? "저장 중…" : `${changes.length}개 변경 사항 저장`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DiffRow({ c, last }: { c: DiffChange; last: boolean }) {
  const isArrayChange = Array.isArray(c.from) && Array.isArray(c.to);
  return (
    <div
      className="px-3.5 py-3"
      style={{
        borderBottom: last ? undefined : "1px solid var(--border)",
      }}
    >
      <div className="font-mono text-[12px] font-semibold" style={{ color: "var(--text)" }}>
        {c.key}
      </div>
      <div className="mt-2 grid gap-1">
        {isArrayChange ? (
          <ArrayDiff from={c.from as unknown[]} to={c.to as unknown[]} />
        ) : (
          <>
            <DiffLine sign="-" value={c.from} />
            <DiffLine sign="+" value={c.to} />
          </>
        )}
      </div>
    </div>
  );
}

function ArrayDiff({ from, to }: { from: unknown[]; to: unknown[] }) {
  const removed = from.filter((x) => !to.includes(x));
  const added = to.filter((x) => !from.includes(x));
  return (
    <>
      {removed.map((x, i) => (
        <DiffLine key={`-${i}`} sign="-" value={x} />
      ))}
      {added.map((x, i) => (
        <DiffLine key={`+${i}`} sign="+" value={x} />
      ))}
      {removed.length === 0 && added.length === 0 && (
        <DiffLine sign="=" value="(순서만 변경)" />
      )}
    </>
  );
}

function DiffLine({ sign, value }: { sign: "+" | "-" | "="; value: unknown }) {
  const isAdd = sign === "+";
  const isNeutral = sign === "=";
  return (
    <div
      className="flex gap-2 rounded-xs px-2 py-0.5 font-mono text-[12px]"
      style={{
        background: isNeutral
          ? "var(--surface-3)"
          : isAdd
            ? "color-mix(in oklab, var(--success-soft) 70%, transparent)"
            : "color-mix(in oklab, var(--danger-soft) 70%, transparent)",
        color: isNeutral
          ? "var(--text-mute)"
          : isAdd
            ? "var(--success)"
            : "var(--danger)",
      }}
    >
      <span className="w-2.5 font-bold">{sign}</span>
      <span style={{ color: "var(--text)" }}>{renderValue(value)}</span>
    </div>
  );
}

function renderValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
