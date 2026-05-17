import { Outlet } from "react-router-dom";
import { useMe } from "@/hooks/useMe";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";

export function AppLayout() {
  const { data: me } = useMe();
  if (!me) return null; // RequireAuth handles redirect; render nothing during the flicker.
  return (
    <div
      className="flex h-screen overflow-hidden"
      style={{ background: "var(--bg)", color: "var(--text)" }}
    >
      <Sidebar me={me} />
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Header me={me} />
        <main
          className="flex-1 overflow-y-auto px-8 pb-12 pt-6"
          style={{ background: "var(--bg)" }}
        >
          <div className="mx-auto w-full max-w-[1440px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
