import { EmptyState } from "@/components/EmptyState";
import { useActivityFeed } from "@/hooks/usePlatformActivity";
import { FeedRow } from "@/pages/platform/activity/FeedRow";

export type FeedCategory = "all" | "ceremony" | "admin-action" | "security-fail";

const FILTERS: { value: FeedCategory; label: string }[] = [
  { value: "all", label: "전체" },
  { value: "admin-action", label: "운영 액션" },
  { value: "security-fail", label: "보안 실패" },
];

export function ActivityFeedPanel({
  tenantIds,
  category,
  onCategoryChange,
}: {
  tenantIds: string[];
  category: FeedCategory;
  onCategoryChange: (c: FeedCategory) => void;
}) {
  const q = useActivityFeed({ category, tenantIds });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <div
      className="rounded-lg border"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div
        className="flex items-center justify-between border-b px-4 py-3"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <div>
          <div className="text-[13px] font-semibold">최근 이벤트</div>
          <div className="text-[11px] text-text-mute">
            필터: {FILTERS.find((f) => f.value === category)?.label} ·{" "}
            {tenantIds.length === 0 ? "모든 tenant" : `${tenantIds.length}개 tenant`}
          </div>
        </div>
        <div className="flex gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => onCategoryChange(f.value)}
              className="rounded-md px-2.5 py-1 text-[12px] font-medium"
              style={{
                background: category === f.value ? "var(--brand-soft)" : "transparent",
                color: category === f.value ? "var(--brand)" : "var(--text-mute)",
              }}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      {q.isLoading && (
        <div className="p-6 text-center text-sm text-text-mute">불러오는 중…</div>
      )}
      {q.isError && (
        <div className="p-6 text-center text-sm text-danger">
          이벤트를 불러오지 못했습니다.{" "}
          <button
            type="button"
            onClick={() => q.refetch()}
            className="ml-1 underline"
          >
            재시도
          </button>
        </div>
      )}
      {!q.isLoading && !q.isError && items.length === 0 && (
        <EmptyState title="선택한 필터에 맞는 이벤트가 없습니다." className="m-4" />
      )}
      {items.map((item) => (
        <FeedRow key={item.id} item={item} />
      ))}
      {q.hasNextPage && (
        <div
          className="border-t p-3 text-center"
          style={{ borderColor: "var(--border-subtle)" }}
        >
          <button
            type="button"
            disabled={q.isFetchingNextPage}
            onClick={() => q.fetchNextPage()}
            className="rounded-md border px-3 py-1.5 text-[12px] font-medium disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            {q.isFetchingNextPage ? "불러오는 중…" : "더 보기"}
          </button>
        </div>
      )}
    </div>
  );
}
