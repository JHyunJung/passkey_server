import * as React from "react";
import {
  ChevronDown,
  KeyRound,
  LogOut,
  Moon,
  Search,
  Sun,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ChangeMyPasswordDialog } from "@/components/ChangeMyPasswordDialog";
import { useLogout } from "@/hooks/useLogout";
import { useTheme } from "@/hooks/useTheme";
import type { Me } from "@/types/api";
import { Breadcrumb } from "./Breadcrumb";

export function Header({ me }: { me: Me }) {
  const logout = useLogout();
  const [pwdOpen, setPwdOpen] = React.useState(false);
  const [theme, toggleTheme] = useTheme();

  return (
    <header
      className="sticky top-0 z-30 flex h-[52px] items-center gap-4 border-b px-6"
      style={{ background: "var(--surface)", borderBottomColor: "var(--border)" }}
    >
      <Breadcrumb />
      <div className="flex-1" />

      {/* Global search — placeholder for ⌘K palette */}
      <button
        type="button"
        className="relative hidden h-8 w-[280px] cursor-pointer items-center gap-2 rounded-md border px-2 pl-[30px] text-left text-[12px] md:flex"
        style={{
          borderColor: "var(--border)",
          background: "var(--surface)",
          color: "var(--text-mute)",
        }}
        onClick={() => {
          // Command palette is out of scope for v1.3 — this slot is wired so the layout matches
          // the Design System reference exactly.
        }}
      >
        <span className="pointer-events-none absolute left-[9px] top-1/2 -translate-y-1/2">
          <Search className="h-3.5 w-3.5" />
        </span>
        <span className="flex-1 truncate">tenant, credential, audit ID 검색…</span>
        <Kbd>⌘K</Kbd>
      </button>

      {/* Theme toggle */}
      <button
        type="button"
        onClick={() => toggleTheme()}
        aria-label="테마 전환"
        className="grid h-8 w-8 place-items-center rounded-md border transition-colors hover:bg-surface-3"
        style={{ borderColor: "var(--border)", background: "var(--surface)" }}
      >
        {theme === "dark" ? (
          <Sun className="h-4 w-4" />
        ) : (
          <Moon className="h-4 w-4" />
        )}
      </button>

      {/* User menu */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="gap-2 px-2 py-1">
            <Avatar name={me.displayName} />
            <div className="hidden flex-col items-start leading-tight md:flex">
              <span className="text-[12px] font-semibold">{me.displayName}</span>
              <span className="text-[10px] text-text-mute">{me.adminId.slice(-8)}</span>
            </div>
            <Badge
              variant={me.role === "PLATFORM_OPERATOR" ? "violet" : "info"}
              className="hidden md:inline-flex"
            >
              {me.role === "PLATFORM_OPERATOR" ? "PLATFORM" : "RP_ADMIN"}
            </Badge>
            <ChevronDown className="h-3.5 w-3.5 text-text-mute" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          <DropdownMenuLabel className="flex flex-col gap-1">
            <span className="text-[13px] font-semibold leading-tight">{me.displayName}</span>
            <span className="font-mono text-[11px] text-text-mute">
              {me.adminId}
            </span>
            <div className="mt-1 flex items-center gap-1.5">
              <Badge variant={me.role === "PLATFORM_OPERATOR" ? "violet" : "info"}>
                {me.role}
              </Badge>
              {me.tenantId && (
                <Badge variant="default" className="font-mono text-[10px]">
                  {me.tenantId.slice(-8)}
                </Badge>
              )}
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setPwdOpen(true)}>
            <KeyRound className="mr-2 h-4 w-4" /> 비밀번호 변경
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => toggleTheme()}>
            {theme === "dark" ? (
              <Sun className="mr-2 h-4 w-4" />
            ) : (
              <Moon className="mr-2 h-4 w-4" />
            )}
            {theme === "dark" ? "라이트 테마" : "다크 테마"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onSelect={() => logout.mutate()}
            className="text-destructive focus:text-destructive"
          >
            <LogOut className="mr-2 h-4 w-4" /> 로그아웃
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ChangeMyPasswordDialog open={pwdOpen} onOpenChange={setPwdOpen} />
    </header>
  );
}

function Avatar({ name }: { name: string }) {
  const initial = name.trim().slice(0, 1).toUpperCase() || "?";
  return (
    <div
      className="grid h-[26px] w-[26px] place-items-center rounded-full text-[12px] font-bold"
      style={{ background: "var(--accent)", color: "var(--accent-fg)" }}
    >
      {initial}
    </div>
  );
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd
      className="inline-flex min-w-[18px] items-center justify-center rounded-xs border px-1.5 py-px font-mono text-[11px]"
      style={{
        borderColor: "var(--border)",
        borderBottomWidth: 2,
        background: "var(--surface)",
        color: "var(--text-soft)",
        boxShadow: "var(--shadow-xs)",
      }}
    >
      {children}
    </kbd>
  );
}

