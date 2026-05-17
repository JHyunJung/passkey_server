import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-pill border border-transparent px-2 py-px text-[11px] font-semibold tracking-tight leading-[1.6]",
  {
    variants: {
      variant: {
        default: "bg-surface-3 text-text-soft",
        secondary: "bg-surface-3 text-text-soft",
        destructive: "bg-danger-soft text-danger",
        success: "bg-success-soft text-success",
        warning: "bg-warning-soft text-warning",
        info: "bg-info-soft text-info",
        violet: "bg-violet-soft text-violet",
        teal: "bg-teal-soft text-teal",
        accent: "bg-accent-soft text-accent",
        outline: "border-border text-text-soft bg-transparent",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
