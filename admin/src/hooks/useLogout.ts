import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { apiPost } from "@/lib/api";

export function useLogout() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return useMutation({
    mutationFn: async () => apiPost<void>("/api/v1/admin/auth/logout"),
    onSettled: () => {
      qc.clear();
      navigate("/", { replace: true });
    },
  });
}
