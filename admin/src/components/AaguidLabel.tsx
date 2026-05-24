import { Badge } from "@/components/ui/badge";
import type { AaguidLabelDto } from "@/types/api";

interface Props {
  aaguid: AaguidLabelDto;
  className?: string;
}

/**
 * Renders the AAGUID label. When fromMds=true the MDS description is shown plain.
 * When false (MDS miss or no blob loaded), the raw UUID is shown with a "미등록" badge so
 * operators can tell certified-FIDO authenticators from platform/community ones.
 */
export function AaguidLabel({ aaguid, className }: Props) {
  return (
    <span className={className ?? "inline-flex items-center gap-1.5"}>
      <span className={aaguid.fromMds ? "" : "font-mono text-xs"}>
        {aaguid.displayName}
      </span>
      {!aaguid.fromMds && aaguid.aaguid !== null && (
        <Badge variant="outline" className="text-xs">
          미등록
        </Badge>
      )}
    </span>
  );
}
