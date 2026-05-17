import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Plus, Save, Undo2, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiGet, apiPut, PasskeyAdminError } from "@/lib/api";
import { useToast } from "@/hooks/useToast";
import { cn } from "@/lib/cn";
import type {
  AttestationMode,
  AttestationPolicyUpsertRequest,
  AttestationPolicyView,
} from "@/types/api";

const MODES: Array<{ v: AttestationMode; t: string; d: string }> = [
  { v: "ANY", t: "ANY", d: "모든 authenticator 허용" },
  { v: "ALLOWLIST", t: "ALLOWLIST", d: "지정된 AAGUID만 허용" },
  { v: "DENYLIST", t: "DENYLIST", d: "지정된 AAGUID만 차단" },
];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function AttestationPolicyTab() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data } = useQuery({
    queryKey: ["attestationPolicy", tenantId],
    queryFn: () =>
      apiGet<AttestationPolicyView>(
        `/api/v1/admin/tenants/${tenantId}/attestation-policy`,
      ),
    enabled: !!tenantId,
  });

  const [form, setForm] = React.useState<AttestationPolicyUpsertRequest | null>(
    null,
  );
  React.useEffect(() => {
    if (data) {
      setForm({
        mode: data.mode,
        allowedAaguids: data.allowed,
        deniedAaguids: data.denied,
        mdsStrict: data.mdsStrict,
        allowZeroAaguid: data.allowZeroAaguid,
        allowSyncable: data.allowSyncable,
      });
    }
  }, [data]);

  const save = useMutation({
    mutationFn: (body: AttestationPolicyUpsertRequest) =>
      apiPut<AttestationPolicyView>(
        `/api/v1/admin/tenants/${tenantId}/attestation-policy`,
        body,
      ),
    onSuccess: () => {
      toast({ variant: "success", title: "AAGUID 정책 저장됨" });
      qc.invalidateQueries({ queryKey: ["attestationPolicy", tenantId] });
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  const [input, setInput] = React.useState("");

  if (!form || !data) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }

  const dirty = JSON.stringify({
    mode: data.mode,
    allowedAaguids: data.allowed,
    deniedAaguids: data.denied,
    mdsStrict: data.mdsStrict,
    allowZeroAaguid: data.allowZeroAaguid,
    allowSyncable: data.allowSyncable,
  }) !== JSON.stringify(form);

  const inputValid = UUID_RE.test(input);
  const activeList =
    form.mode === "ALLOWLIST"
      ? form.allowedAaguids
      : form.mode === "DENYLIST"
        ? form.deniedAaguids
        : [];

  function setActiveList(next: string[]) {
    if (form!.mode === "ALLOWLIST") setForm({ ...form!, allowedAaguids: next });
    else if (form!.mode === "DENYLIST") setForm({ ...form!, deniedAaguids: next });
  }

  function add() {
    if (!inputValid) return;
    const v = input.toLowerCase();
    if (activeList.includes(v)) return;
    setActiveList([...activeList, v]);
    setInput("");
  }

  function remove(u: string) {
    setActiveList(activeList.filter((x) => x !== u));
  }

  function reset() {
    if (!data) return;
    setForm({
      mode: data.mode,
      allowedAaguids: data.allowed,
      deniedAaguids: data.denied,
      mdsStrict: data.mdsStrict,
      allowZeroAaguid: data.allowZeroAaguid,
      allowSyncable: data.allowSyncable,
    });
    setInput("");
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
        <div
          className="flex flex-wrap items-start justify-between gap-3 px-5 py-3.5"
          style={{ borderBottom: "1px solid var(--border-subtle)" }}
        >
          <div className="min-w-0">
            <h3 className="text-[14px] font-semibold tracking-tight">
              AAGUID Attestation Policy
            </h3>
            <p
              className="mt-0.5 text-[12px]"
              style={{ color: "var(--text-mute)" }}
            >
              authenticator 모델별 허용/차단. ANY는 RP가 처음 온보딩할 때만 사용 권장.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
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
              onClick={() => save.mutate(form)}
            >
              <Save className="mr-1 h-3.5 w-3.5" /> 저장
            </Button>
          </div>
        </div>

        <div className="space-y-5 p-5">
          {/* Mode tri-card */}
          <div className="space-y-2">
            <Label className="text-[12px] font-semibold" style={{ color: "var(--text-soft)" }}>
              mode
            </Label>
            <div className="grid max-w-[640px] gap-2 sm:grid-cols-3">
              {MODES.map((o) => {
                const active = form.mode === o.v;
                return (
                  <button
                    key={o.v}
                    type="button"
                    onClick={() => setForm({ ...form, mode: o.v })}
                    className={cn(
                      "rounded-md border p-2.5 text-left transition-colors",
                    )}
                    style={{
                      borderColor: active ? "var(--accent)" : "var(--border)",
                      background: active
                        ? "var(--accent-soft)"
                        : "var(--surface)",
                      color: active ? "var(--accent)" : "var(--text)",
                    }}
                  >
                    <div className="font-mono text-[12px] font-semibold">
                      {o.t}
                    </div>
                    <div
                      className="mt-1 text-[11px]"
                      style={{
                        color: active
                          ? "var(--accent)"
                          : "var(--text-mute)",
                        opacity: active ? 0.8 : 1,
                      }}
                    >
                      {o.d}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* AAGUID list — only when mode != ANY */}
          {form.mode !== "ANY" && (
            <div className="space-y-2">
              <Label className="text-[12px] font-semibold" style={{ color: "var(--text-soft)" }}>
                {form.mode === "ALLOWLIST" ? "허용된 AAGUID" : "차단된 AAGUID"}
              </Label>
              <p
                className="text-[12px]"
                style={{ color: "var(--text-mute)" }}
              >
                UUID v4 형식. FIDO MDS 매핑된 이름이 옆에 표시됩니다.
              </p>
              <div className="flex gap-2">
                <Input
                  className="font-mono"
                  placeholder="ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      add();
                    }
                  }}
                />
                <Button size="sm" disabled={!inputValid} onClick={add}>
                  <Plus className="mr-1 h-3.5 w-3.5" /> 추가
                </Button>
              </div>
              <div
                className="overflow-hidden rounded-md border"
                style={{ borderColor: "var(--border)" }}
              >
                {activeList.length === 0 ? (
                  <div
                    className="p-3.5 text-[12px]"
                    style={{ color: "var(--text-mute)" }}
                  >
                    비어 있음 — 이 상태에서는{" "}
                    {form.mode === "ALLOWLIST"
                      ? "모든 ceremony가 차단"
                      : "모든 ceremony가 허용"}
                    됩니다.
                  </div>
                ) : (
                  activeList.map((u, i) => (
                    <div
                      key={u}
                      className="flex items-center justify-between px-3 py-2"
                      style={{
                        borderBottom:
                          i === activeList.length - 1
                            ? undefined
                            : "1px solid var(--border-subtle)",
                      }}
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <Fingerprint
                          className="h-3.5 w-3.5 shrink-0"
                          style={{ color: "var(--text-mute)" }}
                        />
                        <span className="truncate font-mono text-[12px]">
                          {u}
                        </span>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => remove(u)}
                        aria-label="제거"
                        className="h-7 px-2"
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Toggles */}
          <div className="space-y-2">
            <Label className="text-[12px] font-semibold" style={{ color: "var(--text-soft)" }}>
              추가 옵션
            </Label>
            <ToggleRow
              id="mdsStrict"
              checked={form.mdsStrict}
              onChange={(v) => setForm({ ...form, mdsStrict: v })}
              title="MDS Strict 모드"
              hint="FIDO Metadata Service의 trust anchor만 허용. 서버의 passkey.mds.enabled가 false면 strict tenant의 등록은 차단됩니다."
              badge={form.mdsStrict ? "ON" : "OFF"}
              badgeVariant={form.mdsStrict ? "accent" : "default"}
            />
            <ToggleRow
              id="allowZeroAaguid"
              checked={form.allowZeroAaguid}
              onChange={(v) => setForm({ ...form, allowZeroAaguid: v })}
              title="Zero / NULL AAGUID 허용"
              hint="기본 OFF (보안 권장). 일부 레거시 인증기가 AAGUID를 보고하지 않거나 0으로 보고할 때만 허용하세요."
            />
            <ToggleRow
              id="allowSyncable"
              checked={form.allowSyncable}
              onChange={(v) => setForm({ ...form, allowSyncable: v })}
              title="동기화 가능 (syncable) 인증기 허용"
              hint="기본 ON. iCloud Keychain·Google Password Manager 같은 클라우드 동기화 passkey 등록을 차단하려면 OFF."
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function ToggleRow({
  id,
  checked,
  onChange,
  title,
  hint,
  badge,
  badgeVariant,
}: {
  id: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  title: string;
  hint: string;
  badge?: string;
  badgeVariant?: "accent" | "default";
}) {
  return (
    <div
      className="flex items-start gap-3 rounded-md border p-3"
      style={{
        background: "var(--surface-2)",
        borderColor: "var(--border-subtle)",
      }}
    >
      <Checkbox
        id={id}
        checked={checked}
        onCheckedChange={(v) => onChange(!!v)}
        className="mt-0.5"
      />
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <Label htmlFor={id} className="cursor-pointer text-[13px] font-semibold">
            {title}
          </Label>
          {badge && (
            <Badge variant={badgeVariant ?? "default"} className="text-[10px]">
              {badge}
            </Badge>
          )}
        </div>
        <p
          className="mt-1 text-[12px] leading-snug"
          style={{ color: "var(--text-mute)" }}
        >
          {hint}
        </p>
      </div>
    </div>
  );
}
