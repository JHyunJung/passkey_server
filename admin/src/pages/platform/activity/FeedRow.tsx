import type { FeedItem } from "@/types/api";

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const diff = (Date.now() - then) / 1000;
  if (diff < 60) return "방금";
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`;
  return `${Math.floor(diff / 86400)}일 전`;
}

function categoryDot(category: FeedItem["category"]): string {
  switch (category) {
    case "CEREMONY":
      return "var(--success)";
    case "ADMIN_ACTION":
      return "var(--brand)";
    case "SECURITY_FAIL":
      return "var(--danger)";
  }
}

function eventTypeBadgeColor(category: FeedItem["category"]): {
  bg: string;
  fg: string;
} {
  switch (category) {
    case "CEREMONY":
      return { bg: "var(--success-soft)", fg: "var(--success)" };
    case "ADMIN_ACTION":
      return { bg: "var(--brand-soft)", fg: "var(--brand)" };
    case "SECURITY_FAIL":
      return { bg: "var(--danger-soft)", fg: "var(--danger)" };
  }
}

export function FeedRow({ item }: { item: FeedItem }) {
  const { bg, fg } = eventTypeBadgeColor(item.category);
  return (
    <div
      className="grid grid-cols-[16px_1fr_auto] items-start gap-3 border-b px-4 py-3 last:border-b-0"
      style={{ borderColor: "var(--border-subtle)" }}
    >
      <span
        className="mt-1.5 inline-block h-2 w-2 rounded-full"
        style={{ background: categoryDot(item.category) }}
        aria-hidden
      />
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className="rounded px-1.5 py-0.5 text-[11px] font-semibold tabular-nums"
            style={{ background: bg, color: fg }}
          >
            ● {item.eventType}
          </span>
          <span className="text-[13px] font-medium">{item.tenantName}</span>
          <span className="text-[11px] text-text-mute">
            · {relativeTime(item.createdAt)}
          </span>
        </div>
        <div className="mt-0.5 truncate text-[11px] font-mono text-text-mute">
          actor …{item.actorIdShort ?? "—"} → subject …{item.subjectIdShort ?? "—"}
        </div>
      </div>
    </div>
  );
}
