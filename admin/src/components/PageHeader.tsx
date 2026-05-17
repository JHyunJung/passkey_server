import * as React from "react";
import { cn } from "@/lib/cn";

// Mirrors tokens.css .page__head / .page__title / .page__sub:
//   .page__head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; margin-bottom: 20px; }
//   .page__title { font-size: 22px; font-weight: 600; letter-spacing: var(--letter-tight); }
//   .page__sub { font-size: 13px; color: var(--text-mute); margin-top: 4px; }
export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn("mb-5 flex items-end justify-between gap-4", className)}
    >
      <div className="min-w-0">
        <h1
          className="text-[22px] font-semibold leading-tight tracking-tight"
          style={{ color: "var(--text)" }}
        >
          {title}
        </h1>
        {description && (
          <p className="mt-1 text-[13px]" style={{ color: "var(--text-mute)" }}>
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}
