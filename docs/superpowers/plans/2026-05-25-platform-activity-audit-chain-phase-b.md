# Platform Activity + Audit Chain Monitor — Phase B (Admin SPA) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase A에서 만든 3개 서버 endpoint(`/platform/activity-summary`, `/activity-feed`, `/audit-chain/status` + `POST /verify`)를 소비하는 PLATFORM_OPERATOR 전용 React 페이지 두 개를 도입한다. 사이드바의 mock URL을 실제 라우트로 교체하고, 하단 `AUDIT CHAIN OK` pill을 라이브 데이터로 wire-up.

**Architecture:** React 18 + TypeScript + Vite + TanStack Query + react-router. 라우트는 `RequirePlatformOperator` 가드 아래 두 항목 추가. 데이터는 TanStack Query의 `useQuery` + `useInfiniteQuery`로 캐싱, refetchInterval로 polling. 메트릭 카드는 기존 `MetricCard` 재사용. 필터/페이지네이션/CSV export는 모두 클라이언트 사이드 — 서버 변경 0.

**Tech Stack:** React 18 / TypeScript / Vite / TanStack Query v5 / react-router-dom v6 / Tailwind + shadcn/ui / lucide-react / vitest + Playwright / axios (apiGet/apiPost 헬퍼).

**Spec:** `docs/superpowers/specs/2026-05-24-platform-activity-audit-chain-design.md`
**Phase A baseline:** commit `dff1af5` on branch `worktree-platform-activity-audit-chain`.

---

## File Map

**Create (14)**
- `admin/src/pages/platform/ActivityPage.tsx` — Route entry for `/platform/activity`
- `admin/src/pages/platform/AuditChainMonitorPage.tsx` — Route entry for `/platform/audit-chain`
- `admin/src/pages/platform/activity/ActivityMetricsRow.tsx` — 4 MetricCard tiles
- `admin/src/pages/platform/activity/ActivityFeedPanel.tsx` — Category tabs + infinite scroll feed
- `admin/src/pages/platform/activity/FeedRow.tsx` — Single feed entry
- `admin/src/pages/platform/activity/ActiveTenantsPanel.tsx` — Right-side Top-5
- `admin/src/pages/platform/activity/TenantFilterChips.tsx` — Bottom tenant filter chips
- `admin/src/pages/platform/audit-chain/ChainMetricsRow.tsx` — 4 metric tiles
- `admin/src/pages/platform/audit-chain/TamperedAlertBanner.tsx` — Conditional alert
- `admin/src/pages/platform/audit-chain/ChainStatusTable.tsx` — Per-tenant row table
- `admin/src/hooks/usePlatformActivity.ts` — useActivitySummary + useActivityFeed
- `admin/src/hooks/usePlatformAuditChain.ts` — useAuditChainStatus + useVerifyAllChain mutation
- `admin/src/lib/csv.ts` — Client-side CSV export helper
- `admin/tests/e2e/platform-activity.spec.ts` — Playwright e2e for both pages

**Modify (3)**
- `admin/src/App.tsx` — Add `/platform/activity` + `/platform/audit-chain` routes under `RequirePlatformOperator`
- `admin/src/layout/Sidebar.tsx` — Replace mock URLs with real routes, remove `mock` pill, wire footer pill to live status
- `admin/src/types/api.ts` — Add 8 DTO types

**Optional unit test**
- `admin/tests/unit/categoryBadge.test.tsx` — color mapping + relative time helper

**Run from worktree:** `/Users/jhyun/Git/10-work/crosscert/Passkey/.claude/worktrees/platform-activity-audit-chain/admin`

**Verify before starting any task:** `git rev-parse HEAD` should show `dff1af5` or later (Phase A tip).

---

## Task 1: TypeScript types for new server DTOs

**Files:**
- Modify: `admin/src/types/api.ts`

- [ ] **Step 1: Append the following types at the end of `admin/src/types/api.ts`**

```typescript
// ============================================================================
// Platform Activity / Audit Chain — Phase A endpoints
// See: server/src/main/java/com/crosscert/passkey/admin/controller/
//   AdminPlatformActivityController.java
//   AdminPlatformAuditChainController.java
// ============================================================================

/** Cross-tenant activity Top-5 row. */
export interface TopTenantRow {
  tenantId: string;
  slug: string;
  name: string;
  eventCount24h: number;
  activeCredentials: number;
}

/** HTTP request latency snapshot. null = histogram cold or percentile not published. */
export interface LatencySnapshot {
  avgMs: number | null;
  p95Ms: number | null;
  p99Ms: number | null;
}

/** GET /api/v1/admin/platform/activity-summary?window=24h response.data */
export interface ActivitySummary {
  window: string;
  activity24h: number;
  adminMutations24h: number;
  securityEvents24h: number;
  latency: LatencySnapshot;
  topTenants: TopTenantRow[];
}

/** Audit event category — server-side single source of truth (AuditEventType.category()). */
export type AuditCategory = "CEREMONY" | "ADMIN_ACTION" | "SECURITY_FAIL";

/** GET /api/v1/admin/platform/activity-feed item. */
export interface FeedItem {
  id: string;
  createdAt: string; // ISO 8601
  eventType: string; // AuditEventType.name() — kept as raw string, no exhaustive union
  category: AuditCategory;
  tenantId: string;
  tenantName: string;
  actorType: string;
  actorIdShort: string | null;
  subjectType: string | null;
  subjectIdShort: string | null;
}

/** GET /api/v1/admin/platform/activity-feed response.data */
export interface FeedPage {
  items: FeedItem[];
  nextCursor: string | null;
}

/** A tenant whose hash chain failed validation. */
export interface TamperedTenantSummary {
  tenantId: string;
  slug: string;
  name: string;
  tamperedRowCount: number;
  lastVerifiedAt: string; // ISO 8601
}

/** A single row in the chain status table. */
export interface TenantChainRow {
  tenantId: string;
  slug: string;
  name: string;
  status: "INTACT" | "TAMPERED";
  verifiedRows: number;
  lastVerifiedAt: string;
  tamperedRowCount: number;
}

/** GET /api/v1/admin/platform/audit-chain/status response.data */
export interface AuditChainStatus {
  totalTenants: number;
  intactTenants: number;
  tamperedTenants: TamperedTenantSummary[];
  totalVerifiedRows: number;
  schedulerCron: string;
  schedulerNextRunAt: string;
  adminPollingIntervalSec: number;
  lastVerifyAvgMs: number | null;
  lastVerifyP99Ms: number | null;
  perTenant: TenantChainRow[];
}

/** Per-tenant verify outcome inside VerifyAllResult.perTenant. */
export interface VerifyTenantResult {
  tenantId: string;
  intact: boolean;
  verifiedRows: number;
  tamperedRowCount: number;
  durationMs: number;
}

/** POST /api/v1/admin/platform/audit-chain/verify response.data */
export interface VerifyAllResult {
  startedAt: string;
  completedAt: string;
  tenantsChecked: number;
  tenantsIntact: number;
  tenantsTampered: number;
  perTenant: VerifyTenantResult[];
  errors: string[];
}
```

- [ ] **Step 2: Typecheck**

Run: `cd admin && npm run typecheck`
Expected: 0 errors. (Lints other unrelated files but Phase B types alone shouldn't introduce new issues.)

- [ ] **Step 3: Commit**

```bash
git add admin/src/types/api.ts
git commit -m "feat(admin): TS types for Platform Activity + Audit Chain Phase A endpoints"
```

---

## Task 2: `usePlatformActivity` hook

**Files:**
- Create: `admin/src/hooks/usePlatformActivity.ts`

- [ ] **Step 1: Create the hooks file**

```typescript
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
```

- [ ] **Step 2: Typecheck**

Run: `cd admin && npm run typecheck`
Expected: 0 new errors.

- [ ] **Step 3: Commit**

```bash
git add admin/src/hooks/usePlatformActivity.ts
git commit -m "feat(admin): usePlatformActivity hooks (summary + cursor feed)"
```

---

## Task 3: `usePlatformAuditChain` hook + mutation

**Files:**
- Create: `admin/src/hooks/usePlatformAuditChain.ts`

- [ ] **Step 1: Create the file**

```typescript
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost } from "@/lib/api";
import type { AuditChainStatus, VerifyAllResult } from "@/types/api";

const STATUS_KEY = ["platform", "audit-chain", "status"] as const;

/** Cross-tenant audit chain status. Server-side Caffeine TTL 60s; we refetch on the same cadence. */
export function useAuditChainStatus() {
  return useQuery({
    queryKey: STATUS_KEY,
    queryFn: () =>
      apiGet<AuditChainStatus>("/api/v1/admin/platform/audit-chain/status"),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}

/** "전체 즉시 검증" 버튼. Returns VerifyAllResult. On success, invalidates the status query. */
export function useVerifyAllChain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiPost<VerifyAllResult>(
        "/api/v1/admin/platform/audit-chain/verify",
        undefined,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: STATUS_KEY });
    },
  });
}
```

**Note:** `apiPost<T>(path, body?)` exists in `admin/src/lib/api.ts`. The verify endpoint takes no body — pass `undefined`.

- [ ] **Step 2: Typecheck**

Run: `cd admin && npm run typecheck`
Expected: 0 new errors.

- [ ] **Step 3: Commit**

```bash
git add admin/src/hooks/usePlatformAuditChain.ts
git commit -m "feat(admin): usePlatformAuditChain hooks (status + verifyAll mutation)"
```

---

## Task 4: Activity sub-components — MetricsRow + ActiveTenantsPanel

**Files:**
- Create: `admin/src/pages/platform/activity/ActivityMetricsRow.tsx`
- Create: `admin/src/pages/platform/activity/ActiveTenantsPanel.tsx`

- [ ] **Step 1: Create `ActivityMetricsRow.tsx`**

```typescript
import { MetricCard } from "@/components/MetricCard";
import type { ActivitySummary } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

function fmt(n: number | null): string {
  return n == null ? "—" : nf.format(Math.round(n));
}

export function ActivityMetricsRow({ summary }: { summary?: ActivitySummary }) {
  // While loading, render placeholders to avoid layout shift.
  const activity24h = summary ? nf.format(summary.activity24h) : "—";
  const adminMutations24h = summary ? nf.format(summary.adminMutations24h) : "—";
  const securityEvents24h = summary ? nf.format(summary.securityEvents24h) : "—";
  const avg = summary?.latency.avgMs;
  const p95 = summary?.latency.p95Ms;
  const p99 = summary?.latency.p99Ms;
  const latencyValue = avg == null ? "—" : `${Math.round(avg)}ms`;
  const latencySub =
    p95 == null && p99 == null
      ? "메트릭 워밍업 중"
      : `p95 ${fmt(p95)}ms · p99 ${fmt(p99)}ms`;
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
      <MetricCard
        label="활동 (24H)"
        value={activity24h}
        sub={summary ? `${summary.topTenants.length}개 tenant 합산` : ""}
      />
      <MetricCard
        label="운영 액션 (24H)"
        value={adminMutations24h}
        sub="admin mutation 전체"
      />
      <MetricCard
        label="보안 이벤트 (24H)"
        value={securityEvents24h}
        sub="signature regression + attestation fail"
      />
      <MetricCard label="평균 응답" value={latencyValue} sub={latencySub} />
    </div>
  );
}
```

- [ ] **Step 2: Create `ActiveTenantsPanel.tsx`**

```typescript
import type { TopTenantRow } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

export function ActiveTenantsPanel({ rows }: { rows: TopTenantRow[] }) {
  if (!rows.length) {
    return (
      <div
        className="rounded-lg border p-4 text-sm text-text-mute"
        style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
      >
        활발한 tenant가 없습니다.
      </div>
    );
  }
  return (
    <div
      className="rounded-lg border"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div
        className="border-b px-4 py-3 text-[13px] font-semibold"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        활발한 Tenant
      </div>
      <ul>
        {rows.map((t) => (
          <li
            key={t.tenantId}
            className="flex items-center justify-between border-b px-4 py-2 last:border-b-0"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <div className="flex items-center gap-2">
              <div
                className="flex h-7 w-7 items-center justify-center rounded text-[11px] font-semibold"
                style={{ background: "var(--surface-3)", color: "var(--text)" }}
              >
                {t.name.charAt(0).toUpperCase()}
              </div>
              <div>
                <div className="text-[13px] font-medium">{t.name}</div>
                <div className="text-[11px] text-text-mute">
                  {nf.format(t.activeCredentials)} credentials
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-[13px] tabular-nums">{nf.format(t.eventCount24h)}</div>
              <div className="text-[11px] text-text-mute">24h events</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

- [ ] **Step 3: Typecheck**

Run: `cd admin && npm run typecheck`
Expected: 0 new errors.

- [ ] **Step 4: Commit**

```bash
git add admin/src/pages/platform/activity/ActivityMetricsRow.tsx \
        admin/src/pages/platform/activity/ActiveTenantsPanel.tsx
git commit -m "feat(admin): Activity MetricsRow + ActiveTenantsPanel components"
```

---

## Task 5: Activity feed components — FeedRow + ActivityFeedPanel

**Files:**
- Create: `admin/src/pages/platform/activity/FeedRow.tsx`
- Create: `admin/src/pages/platform/activity/ActivityFeedPanel.tsx`

- [ ] **Step 1: Create `FeedRow.tsx`**

```typescript
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
```

- [ ] **Step 2: Create `ActivityFeedPanel.tsx`**

```typescript
import * as React from "react";
import { EmptyState } from "@/components/EmptyState";
import { useActivityFeed } from "@/hooks/usePlatformActivity";
import { FeedRow } from "@/pages/platform/activity/FeedRow";

type Category = "all" | "ceremony" | "admin-action" | "security-fail";

const FILTERS: { value: Category; label: string }[] = [
  { value: "all", label: "전체" },
  { value: "admin-action", label: "운영 액션" },
  { value: "security-fail", label: "보안 실패" },
];

export function ActivityFeedPanel({ tenantIds }: { tenantIds: string[] }) {
  const [category, setCategory] = React.useState<Category>("all");
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
              onClick={() => setCategory(f.value)}
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
        <div className="border-t p-3 text-center" style={{ borderColor: "var(--border-subtle)" }}>
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
```

- [ ] **Step 3: Typecheck**

Run: `cd admin && npm run typecheck`
Expected: 0 new errors.

- [ ] **Step 4: Commit**

```bash
git add admin/src/pages/platform/activity/FeedRow.tsx \
        admin/src/pages/platform/activity/ActivityFeedPanel.tsx
git commit -m "feat(admin): Activity FeedPanel + FeedRow with category filter + cursor pagination"
```

---

## Task 6: TenantFilterChips + CSV export helper

**Files:**
- Create: `admin/src/pages/platform/activity/TenantFilterChips.tsx`
- Create: `admin/src/lib/csv.ts`

- [ ] **Step 1: Create `TenantFilterChips.tsx`**

```typescript
import type { TopTenantRow } from "@/types/api";

export function TenantFilterChips({
  options,
  selected,
  onToggle,
  onClear,
}: {
  options: TopTenantRow[];
  selected: string[];
  onToggle: (tenantId: string) => void;
  onClear: () => void;
}) {
  if (options.length === 0) return null;
  return (
    <div
      className="rounded-lg border p-4"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div className="mb-2 flex items-center justify-between">
        <div className="text-[13px] font-semibold">Tenant 필터</div>
        {selected.length > 0 && (
          <button
            type="button"
            onClick={onClear}
            className="text-[11px] text-text-mute underline"
          >
            전체 tenant
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onClear}
          className="rounded-pill px-2.5 py-1 text-[11px] font-medium"
          style={{
            background: selected.length === 0 ? "var(--brand-soft)" : "var(--surface-3)",
            color: selected.length === 0 ? "var(--brand)" : "var(--text-mute)",
          }}
        >
          전체 tenant
        </button>
        {options.map((t) => {
          const active = selected.includes(t.tenantId);
          return (
            <button
              key={t.tenantId}
              type="button"
              onClick={() => onToggle(t.tenantId)}
              className="rounded-pill px-2.5 py-1 text-[11px] font-medium"
              style={{
                background: active ? "var(--brand-soft)" : "var(--surface-3)",
                color: active ? "var(--brand)" : "var(--text-mute)",
              }}
            >
              {t.name}
            </button>
          );
        })}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create `csv.ts`**

```typescript
/**
 * Client-side CSV export helpers.
 *
 * Server has no /export endpoint — for Phase B we keep the data plane simple
 * by paginating the existing JSON endpoints client-side and serialising rows in
 * the browser. A future enhancement can move this to a server-streamed CSV.
 */

/** RFC 4180-style escaping. */
function escapeCsvCell(value: unknown): string {
  if (value == null) return "";
  const str = String(value);
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/** Turn an array of plain objects into a CSV string with the given column order. */
export function rowsToCsv<T extends Record<string, unknown>>(
  rows: T[],
  columns: { key: keyof T; header: string }[],
): string {
  const header = columns.map((c) => escapeCsvCell(c.header)).join(",");
  const body = rows
    .map((row) => columns.map((c) => escapeCsvCell(row[c.key])).join(","))
    .join("\n");
  return `${header}\n${body}\n`;
}

/** Trigger a browser download of the CSV string under {@code filename}. */
export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
```

- [ ] **Step 3: Typecheck**

Run: `cd admin && npm run typecheck`

- [ ] **Step 4: Commit**

```bash
git add admin/src/pages/platform/activity/TenantFilterChips.tsx admin/src/lib/csv.ts
git commit -m "feat(admin): TenantFilterChips + csv export helper"
```

---

## Task 7: ActivityPage — route entry assembling all Activity components

**Files:**
- Create: `admin/src/pages/platform/ActivityPage.tsx`

- [ ] **Step 1: Create the page**

```typescript
import * as React from "react";
import { Download, RefreshCw } from "lucide-react";
import { useActivitySummary, useActivityFeed } from "@/hooks/usePlatformActivity";
import { ActivityMetricsRow } from "@/pages/platform/activity/ActivityMetricsRow";
import { ActivityFeedPanel } from "@/pages/platform/activity/ActivityFeedPanel";
import { ActiveTenantsPanel } from "@/pages/platform/activity/ActiveTenantsPanel";
import { TenantFilterChips } from "@/pages/platform/activity/TenantFilterChips";
import { downloadCsv, rowsToCsv } from "@/lib/csv";
import { useToast } from "@/hooks/useToast";

const MAX_EXPORT_ROWS = 5_000;

export function ActivityPage() {
  const [tenantIds, setTenantIds] = React.useState<string[]>([]);
  const summary = useActivitySummary();
  const { toast } = useToast();
  // Re-use a non-mounted infinite-query to fetch up to 5k rows for CSV export.
  const exportFeed = useActivityFeed({ category: "all", tenantIds });

  function toggleTenant(id: string) {
    setTenantIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  async function handleExport() {
    // Paginate up to MAX_EXPORT_ROWS rows, then build CSV in the browser.
    let rows = exportFeed.data?.pages.flatMap((p) => p.items) ?? [];
    let hasNext = exportFeed.hasNextPage;
    let safety = 0;
    while (hasNext && rows.length < MAX_EXPORT_ROWS && safety < 200) {
      const next = await exportFeed.fetchNextPage();
      const all = next.data?.pages.flatMap((p) => p.items) ?? [];
      rows = all;
      hasNext = !!next.hasNextPage;
      safety++;
    }
    if (rows.length === 0) {
      toast({ variant: "default", title: "내보낼 이벤트가 없습니다." });
      return;
    }
    if (rows.length >= MAX_EXPORT_ROWS) {
      toast({
        variant: "default",
        title: `상위 ${MAX_EXPORT_ROWS}건만 내보냈습니다.`,
        description: "기간 또는 tenant 필터를 좁힌 뒤 다시 시도해 주세요.",
      });
    }
    const csv = rowsToCsv(rows.slice(0, MAX_EXPORT_ROWS), [
      { key: "createdAt", header: "createdAt" },
      { key: "eventType", header: "eventType" },
      { key: "category", header: "category" },
      { key: "tenantName", header: "tenantName" },
      { key: "tenantId", header: "tenantId" },
      { key: "actorType", header: "actorType" },
      { key: "actorIdShort", header: "actorIdShort" },
      { key: "subjectType", header: "subjectType" },
      { key: "subjectIdShort", header: "subjectIdShort" },
    ]);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadCsv(`activity-${stamp}.csv`, csv);
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[22px] font-semibold">Activity</h1>
          <p className="text-[13px] text-text-mute">
            전체 tenant의 ceremony · 운영 액션 · 보안 이벤트가 실시간으로 모입니다.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => summary.refetch()}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12px] font-medium"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            <RefreshCw className="h-3.5 w-3.5" /> 새로고침
          </button>
          <button
            type="button"
            onClick={handleExport}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12px] font-medium"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            <Download className="h-3.5 w-3.5" /> 내보내기
          </button>
        </div>
      </div>
      <ActivityMetricsRow summary={summary.data} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <ActivityFeedPanel tenantIds={tenantIds} />
        <ActiveTenantsPanel rows={summary.data?.topTenants ?? []} />
      </div>
      <TenantFilterChips
        options={summary.data?.topTenants ?? []}
        selected={tenantIds}
        onToggle={toggleTenant}
        onClear={() => setTenantIds([])}
      />
    </div>
  );
}
```

- [ ] **Step 2: Typecheck**

Run: `cd admin && npm run typecheck`

- [ ] **Step 3: Commit**

```bash
git add admin/src/pages/platform/ActivityPage.tsx
git commit -m "feat(admin): ActivityPage — route entry assembling metrics + feed + tenant filter + CSV"
```

---

## Task 8: Audit Chain sub-components — ChainMetricsRow + TamperedAlertBanner

**Files:**
- Create: `admin/src/pages/platform/audit-chain/ChainMetricsRow.tsx`
- Create: `admin/src/pages/platform/audit-chain/TamperedAlertBanner.tsx`

- [ ] **Step 1: Create `ChainMetricsRow.tsx`**

```typescript
import { MetricCard } from "@/components/MetricCard";
import type { AuditChainStatus } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

function fmt(n: number | null): string {
  return n == null ? "—" : nf.format(Math.round(n));
}

export function ChainMetricsRow({ status }: { status?: AuditChainStatus }) {
  if (!status) {
    return (
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <MetricCard key={i} label="로딩 중" value="—" />
        ))}
      </div>
    );
  }
  const intactSub =
    status.tamperedTenants.length > 0
      ? `위변조 의심: ${status.tamperedTenants.map((t) => t.name).join(", ")}`
      : "모든 tenant 무결";
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
      <MetricCard
        label="무결 / 전체"
        value={`${status.intactTenants} / ${status.totalTenants}`}
        sub={intactSub}
      />
      <MetricCard
        label="검증된 audit row"
        value={nf.format(status.totalVerifiedRows)}
        sub="누적 chain length"
      />
      <MetricCard
        label="검증 주기"
        value={status.schedulerCron}
        sub={`scheduler · 어드민 새로고침 ${status.adminPollingIntervalSec}s`}
      />
      <MetricCard
        label="평균 chain 검증"
        value={`${fmt(status.lastVerifyAvgMs)}ms`}
        sub={`p99 ${fmt(status.lastVerifyP99Ms)}ms`}
      />
    </div>
  );
}
```

- [ ] **Step 2: Create `TamperedAlertBanner.tsx`**

```typescript
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import type { TamperedTenantSummary } from "@/types/api";
import { useToast } from "@/hooks/useToast";

export function TamperedAlertBanner({
  tampered,
}: {
  tampered: TamperedTenantSummary[];
}) {
  const navigate = useNavigate();
  const { toast } = useToast();
  if (tampered.length === 0) return null;
  const first = tampered[0];
  const heading =
    tampered.length === 1
      ? `${first.name} tenant에서 ${first.tamperedRowCount}개 audit row의 hash가 일치하지 않습니다. DBA + 보안팀 알림 필요.`
      : `${tampered.length}개 tenant에서 위변조 의심 — 자세히 보기`;
  return (
    <div
      className="flex items-center gap-3 rounded-md border p-4"
      style={{
        background: "var(--danger-soft)",
        borderColor: "color-mix(in oklab, var(--danger) 25%, transparent)",
      }}
    >
      <div
        className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
        style={{ background: "var(--danger)" }}
      >
        <AlertTriangle className="h-5 w-5 text-white" />
      </div>
      <div className="flex-1">
        <div
          className="text-[13px] font-semibold"
          style={{ color: "var(--danger)" }}
        >
          위변조 의심 — 즉시 조사 필요
        </div>
        <div className="mt-0.5 text-[12px]" style={{ color: "var(--text)" }}>
          {heading}
        </div>
      </div>
      <button
        type="button"
        onClick={() =>
          navigate(`/tenants/${first.tenantId}/audit-logs`)
        }
        className="rounded-md border px-3 py-1.5 text-[12px] font-medium"
        style={{ borderColor: "var(--border)", color: "var(--text)" }}
      >
        tenant 열기 →
      </button>
      <button
        type="button"
        onClick={() =>
          toast({
            variant: "default",
            title: "Incident 시스템 연동 예정",
            description: "외부 ticket 시스템 통합은 별도 spec으로 진행합니다.",
          })
        }
        className="rounded-md px-3 py-1.5 text-[12px] font-semibold text-white"
        style={{ background: "var(--danger)" }}
      >
        ⚠ Incident 생성
      </button>
    </div>
  );
}
```

- [ ] **Step 3: Typecheck**

Run: `cd admin && npm run typecheck`

- [ ] **Step 4: Commit**

```bash
git add admin/src/pages/platform/audit-chain/ChainMetricsRow.tsx \
        admin/src/pages/platform/audit-chain/TamperedAlertBanner.tsx
git commit -m "feat(admin): Audit Chain MetricsRow + TamperedAlertBanner"
```

---

## Task 9: ChainStatusTable + AuditChainMonitorPage

**Files:**
- Create: `admin/src/pages/platform/audit-chain/ChainStatusTable.tsx`
- Create: `admin/src/pages/platform/AuditChainMonitorPage.tsx`

- [ ] **Step 1: Create `ChainStatusTable.tsx`**

```typescript
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import type { TenantChainRow } from "@/types/api";

const nf = new Intl.NumberFormat("ko-KR");

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const diff = (Date.now() - then) / 1000;
  if (diff < 60) return "방금";
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`;
  return `${Math.floor(diff / 86400)}일 전`;
}

export function ChainStatusTable({ rows }: { rows: TenantChainRow[] }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const intactCount = rows.filter((r) => r.status === "INTACT").length;
  const tamperedCount = rows.length - intactCount;

  const verifyOne = useMutation({
    mutationFn: (tenantId: string) =>
      apiGet<unknown>(`/api/v1/admin/tenants/${tenantId}/audit-logs/verify`),
    onSuccess: (_data, tenantId) => {
      qc.invalidateQueries({ queryKey: ["platform", "audit-chain", "status"] });
      toast({ variant: "success", title: `tenant 검증 완료`, description: tenantId });
    },
    onError: (err: { code?: string; message?: string }) => {
      toast({
        variant: "destructive",
        title: err.code ?? "검증 실패",
        description: err.message ?? "",
      });
    },
  });

  return (
    <div
      className="rounded-lg border"
      style={{ background: "var(--surface)", borderColor: "var(--border-subtle)" }}
    >
      <div
        className="flex items-center justify-between border-b px-4 py-3"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <div className="text-[13px] font-semibold">Tenant별 Chain 상태</div>
        <div className="flex items-center gap-3 text-[11px]">
          <span style={{ color: "var(--success)" }}>● INTACT {intactCount}</span>
          <span style={{ color: "var(--danger)" }}>● TAMPERED {tamperedCount}</span>
        </div>
      </div>
      <table className="w-full text-[13px]">
        <thead>
          <tr
            className="border-b text-[11px] uppercase text-text-mute"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <th className="px-4 py-2 text-left font-semibold">TENANT</th>
            <th className="px-4 py-2 text-left font-semibold">STATUS</th>
            <th className="px-4 py-2 text-right font-semibold">VERIFIED ROWS</th>
            <th className="px-4 py-2 text-left font-semibold">마지막 검증</th>
            <th className="px-4 py-2 text-right font-semibold">액션</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.tenantId} className="border-b last:border-b-0"
                style={{ borderColor: "var(--border-subtle)" }}>
              <td className="px-4 py-2">{r.name}</td>
              <td className="px-4 py-2">
                <span
                  className="rounded-pill px-2 py-0.5 text-[11px] font-semibold"
                  style={{
                    background:
                      r.status === "INTACT" ? "var(--success-soft)" : "var(--danger-soft)",
                    color: r.status === "INTACT" ? "var(--success)" : "var(--danger)",
                  }}
                >
                  ●{" "}
                  {r.status === "INTACT" ? "INTACT" : `TAMPERED · ${r.tamperedRowCount}`}
                </span>
              </td>
              <td className="px-4 py-2 text-right tabular-nums">
                {nf.format(r.verifiedRows)}
              </td>
              <td className="px-4 py-2 text-text-mute">{relativeTime(r.lastVerifiedAt)}</td>
              <td className="px-4 py-2 text-right">
                <button
                  type="button"
                  onClick={() => navigate(`/tenants/${r.tenantId}/audit-logs`)}
                  className="mr-1 rounded-md border px-2 py-1 text-[11px]"
                  style={{ borderColor: "var(--border)" }}
                >
                  열기
                </button>
                <button
                  type="button"
                  disabled={verifyOne.isPending}
                  onClick={() => verifyOne.mutate(r.tenantId)}
                  className="rounded-md border px-2 py-1 text-[11px] disabled:opacity-50"
                  style={{ borderColor: "var(--border)" }}
                >
                  검증
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Create `AuditChainMonitorPage.tsx`**

```typescript
import { Download } from "lucide-react";
import {
  useAuditChainStatus,
  useVerifyAllChain,
} from "@/hooks/usePlatformAuditChain";
import { ChainMetricsRow } from "@/pages/platform/audit-chain/ChainMetricsRow";
import { TamperedAlertBanner } from "@/pages/platform/audit-chain/TamperedAlertBanner";
import { ChainStatusTable } from "@/pages/platform/audit-chain/ChainStatusTable";
import { downloadCsv, rowsToCsv } from "@/lib/csv";
import { useToast } from "@/hooks/useToast";

export function AuditChainMonitorPage() {
  const status = useAuditChainStatus();
  const verifyAll = useVerifyAllChain();
  const { toast } = useToast();

  function handleReport() {
    if (!status.data) return;
    const csv = rowsToCsv(status.data.perTenant, [
      { key: "name", header: "tenant" },
      { key: "slug", header: "slug" },
      { key: "tenantId", header: "tenantId" },
      { key: "status", header: "status" },
      { key: "verifiedRows", header: "verifiedRows" },
      { key: "tamperedRowCount", header: "tamperedRowCount" },
      { key: "lastVerifiedAt", header: "lastVerifiedAt" },
    ]);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadCsv(`audit-chain-report-${stamp}.csv`, csv);
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[22px] font-semibold">Audit Chain Monitor</h1>
          <p className="text-[13px] text-text-mute">
            전체 tenant의 SHA-256 hash chain 무결성 상태.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={!status.data}
            onClick={handleReport}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[12px] font-medium disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--text)" }}
          >
            <Download className="h-3.5 w-3.5" /> 보고서 (CSV)
          </button>
          <button
            type="button"
            disabled={verifyAll.isPending}
            onClick={() =>
              verifyAll.mutate(undefined, {
                onSuccess: (data) =>
                  toast({
                    variant: data.tenantsTampered === 0 ? "success" : "destructive",
                    title: `${data.tenantsChecked}개 tenant 검증 완료`,
                    description: `INTACT ${data.tenantsIntact} · TAMPERED ${data.tenantsTampered}${
                      data.errors.length ? ` · 오류 ${data.errors.length}건` : ""
                    }`,
                  }),
                onError: (err: { code?: string; message?: string }) =>
                  toast({
                    variant: "destructive",
                    title: err.code ?? "검증 실패",
                    description: err.message ?? "",
                  }),
              })
            }
            className="rounded-md px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-50"
            style={{ background: "var(--brand)" }}
          >
            {verifyAll.isPending ? "검증 중…" : "# 전체 즉시 검증"}
          </button>
        </div>
      </div>
      <ChainMetricsRow status={status.data} />
      <TamperedAlertBanner tampered={status.data?.tamperedTenants ?? []} />
      {status.data && <ChainStatusTable rows={status.data.perTenant} />}
    </div>
  );
}
```

- [ ] **Step 3: Typecheck**

Run: `cd admin && npm run typecheck`

- [ ] **Step 4: Commit**

```bash
git add admin/src/pages/platform/audit-chain/ChainStatusTable.tsx \
        admin/src/pages/platform/AuditChainMonitorPage.tsx
git commit -m "feat(admin): AuditChainMonitorPage — ChainStatusTable + verifyAll + CSV report"
```

---

## Task 10: Wire routes in `App.tsx`

**Files:**
- Modify: `admin/src/App.tsx`

- [ ] **Step 1: Add two `lazy()` imports next to existing ones**

Insert after the existing `SystemPage` lazy import (around line 50):

```typescript
const ActivityPage = lazy(() =>
  import("@/pages/platform/ActivityPage").then((m) => ({ default: m.ActivityPage })),
);
const AuditChainMonitorPage = lazy(() =>
  import("@/pages/platform/AuditChainMonitorPage").then((m) => ({
    default: m.AuditChainMonitorPage,
  })),
);
```

- [ ] **Step 2: Add the routes inside the `<RequirePlatformOperator />` block**

Find the existing routes:

```typescript
<Route element={<RequirePlatformOperator />}>
  <Route path="/tenants" element={<TenantsListPage />} />
  <Route path="/admins" element={<AdminUsersPage />} />
  <Route path="/system" element={<SystemPage />} />
</Route>
```

Change to:

```typescript
<Route element={<RequirePlatformOperator />}>
  <Route path="/tenants" element={<TenantsListPage />} />
  <Route path="/platform/activity" element={<ActivityPage />} />
  <Route path="/platform/audit-chain" element={<AuditChainMonitorPage />} />
  <Route path="/admins" element={<AdminUsersPage />} />
  <Route path="/system" element={<SystemPage />} />
</Route>
```

- [ ] **Step 3: Typecheck + build**

Run:
```
cd admin
npm run typecheck
npm run build
```

Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add admin/src/App.tsx
git commit -m "feat(admin): wire /platform/activity + /platform/audit-chain routes"
```

---

## Task 11: Sidebar — replace mock URLs, wire footer pill

**Files:**
- Modify: `admin/src/layout/Sidebar.tsx`

- [ ] **Step 1: Replace mock entries in `NAV_PLATFORM`**

Find:
```typescript
const NAV_PLATFORM: NavItem[] = [
  { to: "/tenants", label: "Tenants", icon: Building2 },
  { to: "/console#me=platform&name=activity", label: "Activity", icon: Activity, external: true, mock: true },
  {
    to: "/console#me=platform&name=audit-chain",
    label: "Audit Chain",
    icon: Hash,
    external: true,
    mock: true,
  },
  { to: "/admins", label: "설정", icon: Cog },
];
```

Replace with:
```typescript
const NAV_PLATFORM: NavItem[] = [
  { to: "/tenants", label: "Tenants", icon: Building2 },
  { to: "/platform/activity", label: "Activity", icon: Activity },
  { to: "/platform/audit-chain", label: "Audit Chain", icon: Hash },
  { to: "/admins", label: "설정", icon: Cog },
];
```

(The `external` and `mock` flags drop with the mock URLs; the `NavItem` shape allows them to be optional already.)

- [ ] **Step 2: Wire the footer pill to live status**

Find the footer pill block (the `Footer · Audit chain status pill` comment region near the bottom of the component). Replace the static `AUDIT CHAIN OK` block with a hook-driven version:

```typescript
// at the top of the Sidebar component body, alongside existing hooks:
const { data: chainStatus } = useAuditChainStatus();
```

Add the import:
```typescript
import { useAuditChainStatus } from "@/hooks/usePlatformAuditChain";
```

Then replace the footer block:

```tsx
{/* Footer · Audit chain status pill */}
<div className="border-t border-border px-3 py-3">
  {(() => {
    const intact =
      !!chainStatus &&
      chainStatus.intactTenants === chainStatus.totalTenants;
    const color = intact ? "var(--success)" : "var(--danger)";
    const bg = intact ? "var(--success-soft)" : "var(--danger-soft)";
    const label = chainStatus
      ? intact
        ? "AUDIT CHAIN OK"
        : "AUDIT CHAIN ALERT"
      : "AUDIT CHAIN …";
    const sub = chainStatus
      ? `${chainStatus.totalVerifiedRows.toLocaleString("ko-KR")}행 · scheduler ${chainStatus.schedulerCron}`
      : "상태 조회 중";
    return (
      <div
        className="space-y-1 rounded-md border px-2.5 py-2"
        style={{
          background: bg,
          borderColor: `color-mix(in oklab, ${color} 20%, transparent)`,
        }}
      >
        <div className="flex items-center gap-1.5 text-[11px] font-semibold" style={{ color }}>
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{
              background: color,
              boxShadow: `0 0 0 3px color-mix(in oklab, ${color} 25%, transparent)`,
            }}
          />
          {label}
        </div>
        <div className="text-[11px] text-text-mute">{sub}</div>
      </div>
    );
  })()}
</div>
```

**Important**: `useAuditChainStatus` polls every 60s. The Sidebar is mounted across all admin routes, so this pill is always live. Tabs/page changes share the same React Query cache key with `AuditChainMonitorPage`, so the data fetch happens at most once per minute.

If `me.role !== "PLATFORM_OPERATOR"`, the user has no PLATFORM access — but the hook will fire anyway. The server returns 403 in that case, which TanStack Query treats as an error. To avoid noisy 403s in the RP_ADMIN console, gate the hook:

```typescript
const isPlatform = me.role === "PLATFORM_OPERATOR";
const { data: chainStatus } = useAuditChainStatus(); // OK to always call
```

Better — extend the hook to accept `enabled`:

In `admin/src/hooks/usePlatformAuditChain.ts`:
```typescript
export function useAuditChainStatus(opts?: { enabled?: boolean }) {
  return useQuery({
    queryKey: STATUS_KEY,
    queryFn: () => apiGet<AuditChainStatus>("/api/v1/admin/platform/audit-chain/status"),
    staleTime: 30_000,
    refetchInterval: 60_000,
    enabled: opts?.enabled ?? true,
  });
}
```

And in Sidebar:
```typescript
const { data: chainStatus } = useAuditChainStatus({ enabled: isPlatform });
```

For RP_ADMIN users, render a generic static pill or simply hide it:
```tsx
{isPlatform ? (
  /* the dynamic pill above */
) : null}
```

- [ ] **Step 3: Typecheck + build**

```
cd admin
npm run typecheck
npm run build
```

- [ ] **Step 4: Commit**

```bash
git add admin/src/layout/Sidebar.tsx admin/src/hooks/usePlatformAuditChain.ts
git commit -m "feat(admin): Sidebar — real /platform routes + live AUDIT CHAIN pill"
```

---

## Task 12: Playwright e2e — both pages reachable + render

**Files:**
- Create: `admin/tests/e2e/platform-activity.spec.ts`

This task requires the full local dev stack running:
1. `scripts/dev-up.sh -y` from the worktree (uses local Passkey server + Admin Vite)
2. Browser-based test points to `http://localhost:5173` (the Playwright config default)

If the dev stack can't be started in the agent's environment, mark this task as DONE_WITH_CONCERNS and document the failure.

- [ ] **Step 1: Create the spec**

```typescript
import { expect, test } from "@playwright/test";

const ADMIN_EMAIL = process.env.PASSKEY_DEV_ADMIN_EMAIL ?? "dev@local.test";
const ADMIN_PASSWORD = process.env.PASSKEY_DEV_ADMIN_PASSWORD ?? "devpassword!";

async function login(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByLabel(/이메일|email/i).fill(ADMIN_EMAIL);
  await page.getByLabel(/비밀번호|password/i).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: /로그인|sign in/i }).click();
  await expect(page).toHaveURL(/\/tenants$/);
}

test.describe("Platform Activity page", () => {
  test("loads metrics + feed for PLATFORM_OPERATOR", async ({ page }) => {
    await login(page);
    await page.goto("/platform/activity");
    await expect(page.getByRole("heading", { name: "Activity" })).toBeVisible();
    // Four metric cards
    await expect(page.getByText("활동 (24H)")).toBeVisible();
    await expect(page.getByText("운영 액션 (24H)")).toBeVisible();
    await expect(page.getByText("보안 이벤트 (24H)")).toBeVisible();
    await expect(page.getByText("평균 응답")).toBeVisible();
    // Filter tabs
    await expect(page.getByRole("button", { name: "전체" })).toBeVisible();
    await expect(page.getByRole("button", { name: "운영 액션" })).toBeVisible();
    await expect(page.getByRole("button", { name: "보안 실패" })).toBeVisible();
    // Feed area or EmptyState (data presence is environment-dependent)
    await expect(
      page.locator("text=/최근 이벤트|선택한 필터에 맞는 이벤트가 없습니다/"),
    ).toBeVisible();
  });
});

test.describe("Audit Chain Monitor page", () => {
  test("loads status + table + verifyAll button", async ({ page }) => {
    await login(page);
    await page.goto("/platform/audit-chain");
    await expect(
      page.getByRole("heading", { name: "Audit Chain Monitor" }),
    ).toBeVisible();
    await expect(page.getByText("무결 / 전체")).toBeVisible();
    await expect(page.getByText("검증된 audit row")).toBeVisible();
    await expect(page.getByText("검증 주기")).toBeVisible();
    await expect(page.getByText("평균 chain 검증")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /전체 즉시 검증/ }),
    ).toBeVisible();
    await expect(page.getByText("Tenant별 Chain 상태")).toBeVisible();
  });
});
```

- [ ] **Step 2: Run the spec**

```
cd admin
npm run e2e -- platform-activity.spec.ts
```

If the dev stack isn't running, the spec will fail with connection errors. Start the stack first:

```
# from worktree root, in a separate terminal
scripts/dev-up.sh -y
```

Expected (with stack up): both tests PASS.

- [ ] **Step 3: Commit**

```bash
git add admin/tests/e2e/platform-activity.spec.ts
git commit -m "test(admin): e2e — /platform/activity + /platform/audit-chain reachable + render"
```

---

## Task 13: Full SPA gate — lint + typecheck + vitest + build

**Files:** (none modified — gate only)

- [ ] **Step 1: Run the full admin checks**

```
cd admin
npm run lint
npm run typecheck
npm run test
npm run build
```

Each step must exit 0. The `test` step runs vitest; if no Phase B unit test was added, it just exercises existing tests.

- [ ] **Step 2: Manual sanity in a browser**

Bring up the dev stack:
```
scripts/dev-up.sh -y
```

Open `http://localhost:5173`. Login as `dev@local.test` / `devpassword!`. Confirm in the browser:
1. Sidebar entries "Activity" and "Audit Chain" link to real pages (no `mock` chip)
2. `/platform/activity` shows 4 metric cards + feed list (or empty state) + tenant filter chips
3. `/platform/audit-chain` shows 4 metric cards + table; if any tenant is tampered, the red banner is visible
4. Click "# 전체 즉시 검증" — toast shows result summary
5. Sidebar footer pill shows live numbers (rows + cron), color green when all intact

Stop the dev stack:
```
scripts/dev-down.sh
```

- [ ] **Step 3: If anything visual is off**, return to the relevant task; otherwise we're done.

No new commit unless a fix is needed. If a fix is needed:

```bash
git add admin/src/...
git commit -m "fix(admin): manual sanity adjustments"
```

---

## Self-Review Checklist (controller — run after all tasks done)

**Spec coverage:**
- §3.1 routes → Task 10
- §3.2 endpoint DTOs → Task 1
- §5.1 routes + guards → Task 10
- §5.2 Activity component tree → Tasks 2, 4, 5, 6, 7
- §5.3 Audit Chain component tree → Tasks 3, 8, 9
- §5.4 sidebar pill wire-up → Task 11
- §5.5 CSV export → Tasks 6, 7, 9
- §5.6 Incident placeholder → Task 8
- §6 error / empty states → Tasks 5, 8
- §7 admin tests (vitest + Playwright) → Task 12, 13
- §8 Phase B rollout → fully covered

**Placeholder scan:** TBD/TODO 0건. Task 11의 RP_ADMIN gating은 if/else 분기로 명시적.

**Type consistency:** `AuditCategory` (uppercase enum) used consistently in types + hooks + components. `FeedItem` shape matches server response. `nextCursor` nullable in both type + hook.

**Scope:** Phase B admin SPA only. No server changes (server changes are Phase A, already merged). 13 tasks, each commit-sized.
