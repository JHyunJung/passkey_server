import { useQuery, useInfiniteQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import type { ActivitySummary, FeedPage } from "@/types/api";

/** 24-hour cross-tenant activity summary. Auto-refetches every 30s. */
export function useActivitySummary() {
  return useQuery({
    queryKey: ["platform", "activity-summary", "24h"] as const,
    queryFn: () =>
      apiGet<ActivitySummary>("/api/v1/admin/platform/activity-summary?window=24h"),
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
}

/**
 * Cursor-paginated cross-tenant audit feed. Category and tenantIds filters are
 * part of the cache key so switching them cleanly resets the pagination cursor.
 */
export function useActivityFeed(opts: {
  category: "all" | "ceremony" | "admin-action" | "security-fail";
  tenantIds: string[]; // empty = all tenants
}) {
  const { category, tenantIds } = opts;
  return useInfiniteQuery({
    queryKey: ["platform", "activity-feed", category, [...tenantIds].sort()] as const,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams();
      if (pageParam) params.set("cursor", pageParam);
      params.set("category", category);
      tenantIds.forEach((id) => params.append("tenantIds", id));
      return apiGet<FeedPage>(`/api/v1/admin/platform/activity-feed?${params.toString()}`);
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    staleTime: 10_000,
    refetchInterval: 10_000,
  });
}
