import * as React from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/CopyButton";
import { apiGet } from "@/lib/api";
import type { EndUserDetailView } from "@/types/api";
import { formatDateTime, lastN } from "@/lib/format";
import { CredentialsTabPanel } from "./user-detail/CredentialsTabPanel";
import { SessionsTabPanel } from "./user-detail/SessionsTabPanel";

function Meta({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={mono ? "mt-0.5 font-mono text-sm" : "mt-0.5 text-sm"}>{value}</div>
    </div>
  );
}

export function UserDetailPage() {
  const { tenantId, tenantUserId } = useParams<{
    tenantId: string;
    tenantUserId: string;
  }>();
  const [search, setSearch] = useSearchParams();
  const tab = search.get("tab") === "sessions" ? "sessions" : "credentials";

  const { data, isLoading, isError } = useQuery({
    queryKey: ["endUser", tenantId, tenantUserId],
    queryFn: () =>
      apiGet<EndUserDetailView>(
        `/api/v1/admin/tenants/${tenantId}/users/${tenantUserId}`,
      ),
    enabled: !!tenantId && !!tenantUserId,
  });

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">불러오는 중…</p>;
  }
  if (isError || !data) {
    return <EmptyState title="사용자를 찾을 수 없습니다." />;
  }

  return (
    <div className="space-y-5">
      <Link
        to={`/tenants/${tenantId}/users`}
        className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="h-3.5 w-3.5" /> 사용자 목록
      </Link>

      <PageHeader
        title={data.displayName ?? data.externalId}
        description={
          <span className="inline-flex items-center gap-1.5">
            External ID: <span className="font-mono">{data.externalId}</span>
            <CopyButton value={data.externalId} />
          </span>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Meta label="내부 ID" value={lastN(data.id, 8)} mono />
        <Meta
          label="자격증명"
          value={
            <span className="inline-flex flex-wrap gap-1.5">
              <Badge variant="success">ACTIVE {data.credentials.active}</Badge>
              <Badge variant="warning">SUSPENDED {data.credentials.suspended}</Badge>
              <Badge variant="outline">REVOKED {data.credentials.revoked}</Badge>
            </span>
          }
        />
        <Meta label="활성 세션" value={data.sessions.active} />
        <Meta
          label="최근 활동"
          value={data.lastActivityAt ? formatDateTime(data.lastActivityAt) : "—"}
        />
      </div>

      <Tabs
        value={tab}
        onValueChange={(v) => {
          const next = new URLSearchParams(search);
          next.set("tab", v);
          setSearch(next, { replace: true });
        }}
      >
        <TabsList>
          <TabsTrigger value="credentials">Credentials</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
        </TabsList>
        <TabsContent value="credentials" className="pt-3">
          <CredentialsTabPanel tenantId={tenantId!} tenantUserId={tenantUserId!} />
        </TabsContent>
        <TabsContent value="sessions" className="pt-3">
          <SessionsTabPanel tenantId={tenantId!} tenantUserId={tenantUserId!} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
