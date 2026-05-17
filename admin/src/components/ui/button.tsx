import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium tracking-tight shadow-xs transition-colors duration-DEFAULT ease-out active:translate-y-px focus-visible:outline-none focus-visible:shadow-focus disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default:
          "border border-accent bg-accent text-accent-foreground hover:bg-accent-hover hover:border-accent-hover active:bg-accent-press active:border-accent-press",
        destructive:
          "border border-danger bg-danger text-white hover:brightness-95",
        outline:
          "border border-border bg-surface text-text hover:bg-surface-2 hover:border-border-strong",
        secondary:
          "border border-border bg-surface text-text hover:bg-surface-3",
        ghost:
          "border border-transparent bg-transparent text-text shadow-none hover:bg-surface-3",
        link: "border-transparent bg-transparent text-accent underline-offset-4 shadow-none hover:underline",
      },
      size: {
        default: "h-8 px-3 text-[13px]",
        sm: "h-7 px-2.5 text-[12px] rounded-sm",
        xs: "h-6 px-2 text-[11px] rounded-sm",
        lg: "h-9 px-4 text-[14px]",
        icon: "h-8 w-8 p-0",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
    );
  },
);
Button.displayName = "Button";

export { buttonVariants };
