interface Props {
  tenantId: string;
  tenantUserId: string;
}

export function SessionsTabPanel({ tenantId, tenantUserId }: Props) {
  return (
    <p className="text-sm text-muted-foreground">
      Sessions 탭은 Task 18에서 구현됩니다. ({tenantId}/{tenantUserId})
    </p>
  );
}
