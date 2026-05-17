import * as React from "react";
import { Navigate, Outlet, useParams } from "react-router-dom";
import { useMe } from "@/hooks/useMe";

function FullPageLoader() {
  return (
    <div className="flex h-screen items-center justify-center text-sm text-muted-foreground">
      불러오는 중…
    </div>
  );
}

/** Gate everything inside the authenticated app shell. */
export function RequireAuth({ children }: { children?: React.ReactNode }) {
  const { data: me, isLoading, isError } = useMe();
  if (isLoading) return <FullPageLoader />;
  if (isError || !me) return <Navigate to="/" replace />;
  return <>{children ?? <Outlet />}</>;
}

/** Block PLATFORM_OPERATOR-only routes for RP_ADMIN. */
export function RequirePlatformOperator({ children }: { children?: React.ReactNode }) {
  const { data: me, isLoading } = useMe();
  if (isLoading) return <FullPageLoader />;
  if (!me) return <Navigate to="/" replace />;
  if (me.role !== "PLATFORM_OPERATOR" && me.tenantId) {
    return <Navigate to={`/tenants/${me.tenantId}/overview`} replace />;
  }
  return <>{children ?? <Outlet />}</>;
}

/** Ensure RP_ADMIN cannot poke into another tenant via URL. */
export function RequireTenantAccess({ children }: { children?: React.ReactNode }) {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { data: me, isLoading } = useMe();
  if (isLoading) return <FullPageLoader />;
  if (!me) return <Navigate to="/" replace />;
  if (me.role !== "PLATFORM_OPERATOR" && me.tenantId !== tenantId) {
    return (
      <div className="m-6 max-w-md rounded-md border border-destructive/40 bg-destructive/5 p-4 text-sm">
        <p className="font-semibold">이 tenant에 대한 권한이 없습니다.</p>
        <p className="mt-2 text-muted-foreground">자신이 속한 tenant 페이지로 이동해 주세요.</p>
      </div>
    );
  }
  return <>{children ?? <Outlet />}</>;
}
