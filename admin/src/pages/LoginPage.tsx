import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Info } from "lucide-react";
import { BrandMark } from "@/components/BrandMark";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiPost, PasskeyAdminError } from "@/lib/api";
import { ME_KEY } from "@/hooks/useMe";
import { useToast } from "@/hooks/useToast";

const schema = z.object({
  email: z.string().email("이메일 형식이 올바르지 않습니다"),
  password: z.string().min(1, "비밀번호를 입력하세요"),
});
type Form = z.infer<typeof schema>;

// Dev-only autofill. Both gates are required so it never reaches a production
// bundle: `import.meta.env.DEV` is constant-folded out of prod builds, and the
// env vars only live in .env.development (never .env.production).
const DEV_AUTOFILL: Partial<Form> = import.meta.env.DEV
  ? {
      email: import.meta.env.VITE_DEV_AUTOFILL_EMAIL as string | undefined,
      password: import.meta.env.VITE_DEV_AUTOFILL_PASSWORD as string | undefined,
    }
  : {};

export function LoginPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { toast } = useToast();
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: DEV_AUTOFILL,
  });

  const login = useMutation({
    mutationFn: async (data: Form) => apiPost<void>("/api/v1/admin/auth/login", data),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ME_KEY });
      const me = qc.getQueryData<{ role: string; tenantId: string | null } | null>(ME_KEY);
      if (me?.role === "PLATFORM_OPERATOR") {
        navigate("/tenants", { replace: true });
      } else if (me?.tenantId) {
        navigate(`/tenants/${me.tenantId}/overview`, { replace: true });
      } else {
        navigate("/", { replace: true });
      }
    },
    onError: (e: PasskeyAdminError) => {
      toast({
        variant: "destructive",
        title: "로그인 실패",
        description: `${e.code} · ${e.message}`,
      });
    },
  });

  const onSubmit = React.useCallback(
    (data: Form) => login.mutate(data),
    [login],
  );

  return (
    <div
      className="grid min-h-screen md:grid-cols-[1.05fr_1fr]"
      style={{ background: "var(--bg)" }}
    >
      {/* Marketing-side panel — hidden on small screens so the form stays usable. */}
      <aside
        className="relative hidden flex-col justify-between overflow-hidden px-12 py-14 text-white md:flex lg:px-16"
        style={{
          background:
            "linear-gradient(135deg, #1c1942 0%, #2e2a78 45%, #4f46e5 100%)",
        }}
      >
        <div className="flex items-center gap-2.5">
          <BrandMark size={28} />
          <span className="text-[15px] font-bold tracking-tight">
            Crosscert Passkey
          </span>
        </div>

        <div>
          <div
            className="mb-3 font-mono text-[13px]"
            style={{ opacity: 0.7 }}
          >
            v1.0 · multi-tenant FIDO2 server
          </div>
          <h1
            className="m-0 max-w-[480px] text-[38px] font-semibold leading-[1.15]"
            style={{ letterSpacing: "-0.02em" }}
          >
            패스키 인증을<br />운영하는 콘솔.
          </h1>
          <p
            className="mt-4 max-w-[460px] text-[14px] leading-relaxed"
            style={{ opacity: 0.8 }}
          >
            tenant 온보딩, API key 회수, credential 폐기, audit hash chain 검증까지 한 곳에서.
            RP의 다음 ceremony가 시작되기 전에 끝낼 수 있도록.
          </p>
          <div className="mt-7 flex gap-5">
            <Stat label="활성 tenant" value="58" />
            <Stat label="ceremony / 24h" value="2.4M" />
            <Stat label="chain 무결성" value="100%" />
          </div>
        </div>

        <div className="text-[12px]" style={{ opacity: 0.6 }}>
          © 2026 Crosscert · 본 콘솔 접근은 모두 audit log에 기록됩니다.
        </div>

        {/* abstract bg shape */}
        <svg
          aria-hidden="true"
          className="pointer-events-none absolute -bottom-36 -right-32 w-[540px]"
          style={{ opacity: 0.18 }}
          viewBox="0 0 200 200"
        >
          <defs>
            <linearGradient id="login-lg1" x1="0" x2="1" y1="0" y2="1">
              <stop stopColor="#fff" />
              <stop offset="1" stopColor="#fff" stopOpacity="0" />
            </linearGradient>
          </defs>
          <circle cx="100" cy="100" r="80" stroke="url(#login-lg1)" strokeWidth="1" fill="none" />
          <circle cx="100" cy="100" r="60" stroke="url(#login-lg1)" strokeWidth="1" fill="none" />
          <circle cx="100" cy="100" r="40" stroke="url(#login-lg1)" strokeWidth="1" fill="none" />
          <circle cx="100" cy="100" r="20" stroke="url(#login-lg1)" strokeWidth="1" fill="none" />
        </svg>
      </aside>

      {/* Form side */}
      <div className="flex items-center justify-center px-6 py-10">
        <form
          onSubmit={handleSubmit(onSubmit)}
          className="w-full max-w-[380px]"
        >
          {/* Mobile-only brand (since the marketing panel is hidden under md) */}
          <div className="mb-6 flex items-center gap-2.5 md:hidden">
            <BrandMark size={26} />
            <span className="text-[14px] font-bold tracking-tight">
              Crosscert Passkey
            </span>
          </div>

          <h2
            className="m-0 text-[24px] font-semibold tracking-tight"
            style={{ color: "var(--text)" }}
          >
            관리자 로그인
          </h2>
          <p
            className="mb-7 mt-1.5 text-[13px]"
            style={{ color: "var(--text-mute)" }}
          >
            Crosscert Passkey 콘솔에 접근하려면 운영자 계정으로 로그인하세요.
          </p>

          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="email">이메일</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                autoFocus
                {...register("email")}
              />
              {errors.email && (
                <p className="text-xs text-destructive">{errors.email.message}</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">비밀번호</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                {...register("password")}
              />
              {errors.password && (
                <p className="text-xs text-destructive">{errors.password.message}</p>
              )}
            </div>
            <Button
              type="submit"
              disabled={isSubmitting || login.isPending}
              className="mt-1 h-[38px] w-full"
            >
              {login.isPending ? "확인 중…" : "로그인"}
            </Button>
          </div>

          <div
            className="mt-6 flex gap-2 rounded-md px-3 py-2.5 text-[11px]"
            style={{
              background: "var(--surface-3)",
              color: "var(--text-mute)",
            }}
          >
            <Info className="mt-px h-3.5 w-3.5 shrink-0" />
            <span>
              30분 동안 활동이 없으면 자동 로그아웃됩니다. 모든 mutation은 audit chain에 기록됩니다.
            </span>
          </div>
        </form>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div
        className="text-[11px] font-semibold uppercase"
        style={{ opacity: 0.7, letterSpacing: "0.06em" }}
      >
        {label}
      </div>
      <div className="mt-1 text-[22px] font-semibold">{value}</div>
    </div>
  );
}
