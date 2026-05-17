import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { apiGet } from "@/lib/api";
import { setSentryUser } from "@/lib/sentry";
import type { Me } from "@/types/api";

const ME_KEY = ["me"] as const;
const FIVE_MIN = 5 * 60_000;

export function useMe() {
  const query = useQuery<Me | null>({
    queryKey: ME_KEY,
    queryFn: async () => apiGet<Me>("/api/v1/admin/me"),
    staleTime: FIVE_MIN,
    retry: false,
  });
  // Tag Sentry events with adminId only — email / IP are scrubbed in sentry.ts beforeSend.
  useEffect(() => {
    if (query.data?.adminId) {
      setSentryUser({ id: query.data.adminId });
    } else {
      setSentryUser(null);
    }
  }, [query.data?.adminId]);
  return query;
}

/** Hook returning a function that clears the cached identity (used on 401 / logout). */
export function useClearMe() {
  const qc = useQueryClient();
  return () => {
    qc.setQueryData(ME_KEY, null);
    qc.removeQueries({ queryKey: ME_KEY });
    setSentryUser(null);
  };
}

export { ME_KEY };
