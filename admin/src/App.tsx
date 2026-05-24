import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/layout/AppLayout";
import {
  RequireAuth,
  RequirePlatformOperator,
  RequireTenantAccess,
} from "@/lib/guard";
import { LoginPage } from "@/pages/LoginPage";
import { useMe } from "@/hooks/useMe";

const TenantsListPage = lazy(() =>
  import("@/pages/TenantsListPage").then((m) => ({ default: m.TenantsListPage })),
);
const TenantDetailPage = lazy(() =>
  import("@/pages/TenantDetailPage").then((m) => ({ default: m.TenantDetailPage })),
);
const OverviewTab = lazy(() =>
  import("@/pages/tenant/OverviewTab").then((m) => ({ default: m.OverviewTab })),
);
const WebauthnConfigTab = lazy(() =>
  import("@/pages/tenant/WebauthnConfigTab").then((m) => ({ default: m.WebauthnConfigTab })),
);
const AttestationPolicyTab = lazy(() =>
  import("@/pages/tenant/AttestationPolicyTab").then((m) => ({
    default: m.AttestationPolicyTab,
  })),
);
const ApiKeysTab = lazy(() =>
  import("@/pages/tenant/ApiKeysTab").then((m) => ({ default: m.ApiKeysTab })),
);
const UsersTab = lazy(() =>
  import("@/pages/tenant/UsersTab").then((m) => ({ default: m.UsersTab })),
);
const UserDetailPage = lazy(() =>
  import("@/pages/tenant/UserDetailPage").then((m) => ({ default: m.UserDetailPage })),
);
const CredentialsTab = lazy(() =>
  import("@/pages/tenant/CredentialsTab").then((m) => ({ default: m.CredentialsTab })),
);
const AuditTab = lazy(() =>
  import("@/pages/tenant/AuditTab").then((m) => ({ default: m.AuditTab })),
);
const FunnelTab = lazy(() =>
  import("@/pages/tenant/FunnelTab").then((m) => ({ default: m.FunnelTab })),
);
const AdminUsersPage = lazy(() =>
  import("@/pages/AdminUsersPage").then((m) => ({ default: m.AdminUsersPage })),
);
const SystemPage = lazy(() =>
  import("@/pages/SystemPage").then((m) => ({ default: m.SystemPage })),
);
const ActivityPage = lazy(() =>
  import("@/pages/platform/ActivityPage").then((m) => ({ default: m.ActivityPage })),
);
const AuditChainMonitorPage = lazy(() =>
  import("@/pages/platform/AuditChainMonitorPage").then((m) => ({
    default: m.AuditChainMonitorPage,
  })),
);
function PageFallback() {
  return (
    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
      불러오는 중…
    </div>
  );
}

function RootRedirect() {
  const { data: me, isLoading } = useMe();
  if (isLoading) return <PageFallback />;
  if (!me) return <LoginPage />;
  if (me.role === "PLATFORM_OPERATOR") return <Navigate to="/tenants" replace />;
  if (me.tenantId) return <Navigate to={`/tenants/${me.tenantId}/overview`} replace />;
  return <LoginPage />;
}

export function App() {
  return (
    <Suspense fallback={<PageFallback />}>
      <Routes>
        <Route path="/" element={<RootRedirect />} />
        <Route element={<RequireAuth />}>
          <Route element={<AppLayout />}>
            <Route element={<RequirePlatformOperator />}>
              <Route path="/tenants" element={<TenantsListPage />} />
              <Route path="/platform/activity" element={<ActivityPage />} />
              <Route path="/platform/audit-chain" element={<AuditChainMonitorPage />} />
              <Route path="/admins" element={<AdminUsersPage />} />
              <Route path="/system" element={<SystemPage />} />
            </Route>
            <Route path="/tenants/:tenantId" element={<TenantDetailPage />}>
              <Route element={<RequireTenantAccess />}>
                <Route index element={<Navigate to="overview" replace />} />
                <Route path="overview" element={<OverviewTab />} />
                <Route path="webauthn-config" element={<WebauthnConfigTab />} />
                <Route path="attestation-policy" element={<AttestationPolicyTab />} />
                <Route path="api-keys" element={<ApiKeysTab />} />
                <Route path="users" element={<UsersTab />} />
                <Route path="users/:tenantUserId" element={<UserDetailPage />} />
                <Route path="credentials" element={<CredentialsTab />} />
                <Route path="audit-logs" element={<AuditTab />} />
                <Route path="funnel" element={<FunnelTab />} />
              </Route>
            </Route>
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}
