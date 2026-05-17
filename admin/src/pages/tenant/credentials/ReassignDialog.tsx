import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
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
import { apiGet, apiPost, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { lastN } from "@/lib/format";
import type {
  CredentialView,
  PageResponse,
  TenantView,
} from "@/types/api";

interface Props {
  sourceTenantId: string;
  sourceTenantSlug: string | undefined;
  target: CredentialView | null;
  onOpenChange: (open: boolean) => void;
}

export function ReassignDialog({
  sourceTenantId,
  sourceTenantSlug,
  target,
  onOpenChange,
}: Props) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const open = target !== null;

  const [targetTenantId, setTargetTenantId] = React.useState("");
  const [targetTenantUserId, setTargetTenantUserId] = React.useState("");
  const [slugInput, setSlugInput] = React.useState("");

  React.useEffect(() => {
    if (!open) {
      setTargetTenantId("");
      setTargetTenantUserId("");
      setSlugInput("");
    }
  }, [open]);

  // List all tenants for the target selector. PLATFORM_OPERATOR sees every tenant.
  const { data: tenants } = useQuery({
    queryKey: ["tenants", "all-for-reassign"],
    queryFn: () =>
      apiGet<PageResponse<TenantView>>(`/api/v1/admin/tenants?page=0&size=200`),
    enabled: open,
  });
  const otherTenants =
    tenants?.content.filter((t) => t.id !== sourceTenantId && t.status === "ACTIVE") ?? [];

  const reassign = useMutation({
    mutationFn: () =>
      apiPost<CredentialView>(
        `/api/v1/admin/tenants/${sourceTenantId}/credentials/${target!.id}/reassign`,
        { targetTenantId, targetTenantUserId },
      ),
    onSuccess: () => {
      toast({ variant: "success", title: "Credential 이관 완료" });
      qc.invalidateQueries({ queryKey: ["credentials", sourceTenantId] });
      onOpenChange(false);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const canSubmit =
    targetTenantId.length > 0 &&
    targetTenantUserId.length > 0 &&
    sourceTenantSlug !== undefined &&
    slugInput === sourceTenantSlug &&
    !reassign.isPending;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onOpenChange(false)}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>⚠️ Credential을 다른 tenant로 이관</DialogTitle>
          <DialogDescription>
            이 작업은 credential을 다른 tenant로 영구 이동시킵니다. 두 tenant의{" "}
            <strong>rpId가 동일해야</strong> 작동합니다. source tenant의 모든 refresh token이 함께
            회수됩니다.
          </DialogDescription>
        </DialogHeader>
        {target && (
          <div className="space-y-3 text-sm">
            <div className="rounded-md border bg-muted/40 p-3 font-mono text-xs">
              Credential ID: {lastN(target.credentialId, 12)}
              <br />
              Source User: {lastN(target.tenantUserId, 8)}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="targetTenant">Target Tenant</Label>
              <Select value={targetTenantId} onValueChange={setTargetTenantId}>
                <SelectTrigger id="targetTenant">
                  <SelectValue placeholder="이관할 tenant 선택" />
                </SelectTrigger>
                <SelectContent>
                  {otherTenants.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name} ({t.slug})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="targetUser">Target TenantUser ID</Label>
              <Input
                id="targetUser"
                value={targetTenantUserId}
                onChange={(e) => setTargetTenantUserId(e.target.value)}
                placeholder="UUID — target tenant의 기존 사용자"
              />
              <p className="text-xs text-muted-foreground">
                대상 tenant에 이미 존재하는 TenantUser의 UUID를 입력하세요. rare op이므로 검색
                UI는 v1.4에서 제공됩니다.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="slugConfirm">
                확인: source tenant slug{" "}
                <code className="rounded bg-muted px-1">{sourceTenantSlug ?? "..."}</code> 입력
              </Label>
              <Input
                id="slugConfirm"
                value={slugInput}
                placeholder={sourceTenantSlug ?? ""}
                onChange={(e) => setSlugInput(e.target.value)}
              />
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button
            variant="destructive"
            disabled={!canSubmit}
            onClick={() => reassign.mutate()}
          >
            {reassign.isPending ? "이관 중…" : "이관 실행"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
