import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost } from "@/lib/api";
import type { AuditChainStatus, VerifyAllResult } from "@/types/api";

const STATUS_KEY = ["platform", "audit-chain", "status"] as const;

/**
 * Cross-tenant audit chain status. Server-side Caffeine TTL 60s; we refetch on the
 * same cadence. Pass {@code enabled: false} when the caller isn't a PLATFORM_OPERATOR
 * to suppress the 403-noise (e.g. when the Sidebar mounts for an RP_ADMIN user).
 */
export function useAuditChainStatus(opts?: { enabled?: boolean }) {
  return useQuery({
    queryKey: STATUS_KEY,
    queryFn: () =>
      apiGet<AuditChainStatus>("/api/v1/admin/platform/audit-chain/status"),
    staleTime: 30_000,
    refetchInterval: 60_000,
    enabled: opts?.enabled ?? true,
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
