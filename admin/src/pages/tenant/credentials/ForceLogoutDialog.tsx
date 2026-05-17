import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { apiPost, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { lastN } from "@/lib/format";

interface ForceLogoutDialogProps {
  tenantId: string;
  tenantUserId: string | null;
  affectedCredentialCount: number;
  onOpenChange: (open: boolean) => void;
}

interface ForceLogoutResult {
  revokedCount: number;
}

export function ForceLogoutDialog({
  tenantId,
  tenantUserId,
  affectedCredentialCount,
  onOpenChange,
}: ForceLogoutDialogProps) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const open = tenantUserId !== null;

  const mutation = useMutation({
    mutationFn: () =>
      apiPost<ForceLogoutResult>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}/logout-all`,
      ),
    onSuccess: (result) => {
      toast({
        variant: "success",
        title: "세션 종료 완료",
        description: `refresh token ${result.revokedCount}개를 회수했습니다.`,
      });
      qc.invalidateQueries({ queryKey: ["credentials", tenantId] });
      qc.invalidateQueries({ queryKey: ["auditLogs", tenantId] });
      onOpenChange(false);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onOpenChange(false)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>이 사용자의 모든 세션 종료</DialogTitle>
          <DialogDescription>
            해당 사용자의 활성 refresh token이 모두 즉시 회수됩니다. 다음 access token 갱신 시점에
            모든 기기·브라우저에서 강제 로그아웃됩니다. credential은 그대로 유지됩니다.
          </DialogDescription>
        </DialogHeader>
        {tenantUserId && (
          <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-xs">
            <div className="font-mono">User: {lastN(tenantUserId, 12)}</div>
            <div className="text-muted-foreground">
              이 사용자의 활성 credential: <strong>{affectedCredentialCount}</strong>건 (대상은
              세션이지 credential이 아닙니다)
            </div>
          </div>
        )}
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={mutation.isPending}
          >
            취소
          </Button>
          <Button
            variant="destructive"
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
          >
            {mutation.isPending ? "종료 중…" : "모든 세션 종료"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
