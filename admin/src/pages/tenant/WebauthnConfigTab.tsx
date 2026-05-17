import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Save, Undo2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
import { ChipInput } from "@/components/ChipInput";
import { DiffDialog, diffObjects } from "@/components/DiffDialog";
import { Segmented } from "@/components/Segmented";
import { apiGet, apiPut, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import type {
  AttestationConveyance,
  CredProtectPolicy,
  ResidentKeyPolicy,
  TenantView,
  UserVerificationPolicy,
  WebauthnConfigUpsertRequest,
  WebauthnConfigView,
} from "@/types/api";

const UV_OPTIONS = ["REQUIRED", "PREFERRED", "DISCOURAGED"] as const;
const AC_OPTIONS = ["NONE", "INDIRECT", "DIRECT", "ENTERPRISE"] as const;
const RK_OPTIONS = ["REQUIRED", "PREFERRED", "DISCOURAGED"] as const;
const CP_OPTIONS: CredProtectPolicy[] = [
  "NONE",
  "UV_OPTIONAL",
  "UV_OPTIONAL_WITH_CREDID",
  "UV_REQUIRED",
];

export function WebauthnConfigTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data } = useQuery({
    queryKey: ["webauthnConfig", tenantId],
    queryFn: () =>
      apiGet<WebauthnConfigView>(
        `/api/v1/admin/tenants/${tenantId}/webauthn-config`,
      ),
    enabled: !!tenantId,
  });

  const { data: tenant } = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiGet<TenantView>(`/api/v1/admin/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const [form, setForm] = React.useState<WebauthnConfigUpsertRequest | null>(null);
  React.useEffect(() => {
    if (data) {
      setForm({
        rpId: data.rpId,
        rpName: data.rpName,
        origins: data.origins,
        timeoutMs: data.timeoutMs,
        userVerification: data.userVerification,
        attestationConveyance: data.attestationConveyance,
        residentKey: data.residentKey,
        credProtect: data.credProtect,
      });
    }
  }, [data]);

  const save = useMutation({
    mutationFn: (body: WebauthnConfigUpsertRequest) =>
      apiPut<WebauthnConfigView>(
        `/api/v1/admin/tenants/${tenantId}/webauthn-config`,
        body,
      ),
    onSuccess: () => {
      toast({ variant: "success", title: "WebAuthn config 저장됨" });
      qc.invalidateQueries({ queryKey: ["webauthnConfig", tenantId] });
      setDiffOpen(false);
      setRpIdConfirmOpen(false);
      setSlugInput("");
    },
    onError: (e: PasskeyAdminError) => {
      toast({ variant: "destructive", title: e.code, description: e.message });
    },
  });

  const [diffOpen, setDiffOpen] = React.useState(false);
  const [rpIdConfirmOpen, setRpIdConfirmOpen] = React.useState(false);
  const [slugInput, setSlugInput] = React.useState("");

  if (!form || !data) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }

  const dirty = JSON.stringify(data) !== JSON.stringify(form);
  const changes = dirty
    ? diffObjects(
        data as unknown as Record<string, unknown>,
        form as unknown as Record<string, unknown>,
      )
    : [];
  const rpIdChanged = form.rpId !== data.rpId;

  function reset() {
    if (!data) return;
    setForm({
      rpId: data.rpId,
      rpName: data.rpName,
      origins: data.origins,
      timeoutMs: data.timeoutMs,
      userVerification: data.userVerification,
      attestationConveyance: data.attestationConveyance,
      residentKey: data.residentKey,
      credProtect: data.credProtect,
    });
  }

  function attemptSave() {
    if (form!.origins.length === 0) {
      toast({
        variant: "destructive",
        title: "origin 1개 이상 필요",
        description: "최소 1개의 origin을 추가하세요.",
      });
      return;
    }
    setDiffOpen(true);
  }

  function confirmFromDiff() {
    if (rpIdChanged) {
      setDiffOpen(false);
      setSlugInput("");
      setRpIdConfirmOpen(true);
      return;
    }
    save.mutate(form!);
  }

  return (
    <div className="space-y-4">
      <div
        className="overflow-hidden rounded-lg border"
        style={{
          background: "var(--surface)",
          borderColor: "var(--border-subtle)",
          boxShadow: "var(--shadow-xs)",
        }}
      >
        {/* Card head */}
        <div
          className="flex flex-wrap items-start justify-between gap-3 px-5 py-3.5"
          style={{ borderBottom: "1px solid var(--border-subtle)" }}
        >
          <div className="min-w-0">
            <h3 className="text-[14px] font-semibold tracking-tight">
              WebAuthn Configuration
            </h3>
            <p
              className="mt-0.5 text-[12px]"
              style={{ color: "var(--text-mute)" }}
            >
              RP가 ceremony 요청 시 사용하는 파라미터. 변경은 즉시 다음 ceremony부터 적용됩니다.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {dirty && (
              <Badge variant="warning" className="gap-1">
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ background: "currentColor" }}
                />
                변경 사항 {changes.length}건
              </Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              disabled={!dirty || save.isPending}
              onClick={reset}
            >
              <Undo2 className="mr-1 h-3.5 w-3.5" /> 되돌리기
            </Button>
            <Button
              size="sm"
              disabled={!dirty || save.isPending}
              onClick={attemptSave}
            >
              <Save className="mr-1 h-3.5 w-3.5" /> 저장…
            </Button>
          </div>
        </div>

        {/* Body */}
        <div className="p-5">
          <div className="grid gap-6 md:grid-cols-2">
            {/* Col 1 */}
            <div className="space-y-4">
              <FieldRow
                label="rpId"
                hint="Relying Party의 hostname. 변경 시 기존 credential이 무효화될 수 있습니다."
              >
                <Input
                  className="font-mono"
                  value={form.rpId}
                  onChange={(e) => setForm({ ...form, rpId: e.target.value })}
                />
              </FieldRow>
              <FieldRow
                label="rpName"
                hint="UA 선택 화면에 표시되는 표시 이름."
              >
                <Input
                  value={form.rpName}
                  onChange={(e) => setForm({ ...form, rpName: e.target.value })}
                />
              </FieldRow>
              <FieldRow
                label="timeoutMs"
                hint="ceremony 타임아웃 (밀리초). 권장 60000–120000."
              >
                <Input
                  type="number"
                  className="font-mono"
                  min={1000}
                  value={form.timeoutMs}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      timeoutMs: Number(e.target.value) || 0,
                    })
                  }
                />
              </FieldRow>
              <FieldRow
                label="credProtect"
                hint="CTAP2 credProtect extension. UV_OPTIONAL 기본, UV_REQUIRED 시 UV 없이 차단."
              >
                <Select
                  value={form.credProtect}
                  onValueChange={(v) =>
                    setForm({ ...form, credProtect: v as CredProtectPolicy })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CP_OPTIONS.map((o) => (
                      <SelectItem key={o} value={o}>
                        {o}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FieldRow>
            </div>

            {/* Col 2 */}
            <div className="space-y-4">
              <FieldRow
                label="origins"
                hint="ceremony가 시작될 수 있는 origin. 정확히 일치해야 함."
              >
                <ChipInput
                  value={form.origins}
                  onChange={(origins) => setForm({ ...form, origins })}
                  placeholder="https://… 입력 후 Enter"
                  validate={(s) =>
                    /^https?:\/\//.test(s)
                      ? null
                      : "https:// 또는 http://로 시작해야 합니다."
                  }
                />
              </FieldRow>
              <FieldRow
                label="userVerification"
                hint="UV flag. REQUIRED 권장 — PIN/biometric 강제."
              >
                <Segmented
                  value={form.userVerification}
                  onChange={(v) =>
                    setForm({ ...form, userVerification: v as UserVerificationPolicy })
                  }
                  options={UV_OPTIONS}
                />
              </FieldRow>
              <FieldRow
                label="attestationConveyance"
                hint="attestation 객체 전달 모드."
              >
                <Segmented
                  value={form.attestationConveyance}
                  onChange={(v) =>
                    setForm({ ...form, attestationConveyance: v as AttestationConveyance })
                  }
                  options={AC_OPTIONS}
                />
              </FieldRow>
              <FieldRow
                label="residentKey"
                hint="username-less / discoverable 흐름 강제 시 REQUIRED."
              >
                <Segmented
                  value={form.residentKey}
                  onChange={(v) =>
                    setForm({ ...form, residentKey: v as ResidentKeyPolicy })
                  }
                  options={RK_OPTIONS}
                />
              </FieldRow>
            </div>
          </div>
        </div>
      </div>

      {/* rpId change banner */}
      {rpIdChanged && (
        <div
          className="rounded-lg border p-4"
          style={{
            background: "var(--danger-soft)",
            borderColor: "color-mix(in oklab, var(--danger) 25%, var(--border))",
          }}
        >
          <div className="flex gap-2.5">
            <AlertTriangle
              className="mt-0.5 h-5 w-5 shrink-0"
              style={{ color: "var(--danger)" }}
            />
            <div>
              <div
                className="text-[13px] font-semibold"
                style={{ color: "var(--danger)" }}
              >
                rpId가 변경됩니다.
              </div>
              <div
                className="mt-1 text-[13px]"
                style={{ color: "var(--text)" }}
              >
                이 tenant의 모든 기존 credential이 다음 ceremony부터 인증에 실패할 수 있습니다. 사용자에게 재등록 안내가 필요합니다.
              </div>
            </div>
          </div>
        </div>
      )}

      <DiffDialog
        open={diffOpen}
        onOpenChange={setDiffOpen}
        changes={changes}
        onConfirm={confirmFromDiff}
        busy={save.isPending}
        auditEventType="WEBAUTHN_CONFIG_UPDATED"
      />

      <Dialog open={rpIdConfirmOpen} onOpenChange={setRpIdConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>⚠️ rpId 변경 확인</DialogTitle>
            <DialogDescription>
              rpId를 변경하면 <strong>이 tenant의 모든 기존 credential이 무효화</strong>되어 사용자들이 다시 등록해야 합니다. 진행하려면 tenant slug{" "}
              <code className="rounded bg-muted px-1">
                {tenant?.slug ?? "..."}
              </code>
              를 입력하세요.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 text-sm">
            <div className="rounded-md border bg-muted/40 p-3 font-mono text-xs">
              <div>현재 rpId: {data.rpId}</div>
              <div>새 rpId: {form.rpId}</div>
            </div>
            <Input
              autoFocus
              value={slugInput}
              placeholder={tenant?.slug ?? ""}
              onChange={(e) => setSlugInput(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRpIdConfirmOpen(false)}>
              취소
            </Button>
            <Button
              variant="destructive"
              disabled={
                !tenant || slugInput !== tenant.slug || save.isPending
              }
              onClick={() => save.mutate(form)}
            >
              {save.isPending ? "저장 중…" : "확인하고 저장"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function FieldRow({
  label,
  hint,
  children,
}: {
  label: React.ReactNode;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label className="block text-[12px] font-semibold" style={{ color: "var(--text-soft)" }}>
        {label}
      </Label>
      {children}
      {hint && (
        <p
          className="text-[12px] leading-snug"
          style={{ color: "var(--text-mute)" }}
        >
          {hint}
        </p>
      )}
    </div>
  );
}
