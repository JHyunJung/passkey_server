import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // dev proxy keeps the SPA same-origin against the Spring backend.
      // Production builds use VITE_API_BASE_URL pointing to the API host.
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
        secure: false,
        // Drop the `Secure` flag from Set-Cookie so browsers accept session cookies over plain
        // http://localhost during development. Without this, Spring Session's Secure-flagged
        // PASSKEY_SESSION cookie is silently rejected and the user never appears authenticated.
        cookieDomainRewrite: "localhost",
        configure: (proxy) => {
          proxy.on("proxyRes", (proxyRes) => {
            const setCookie = proxyRes.headers["set-cookie"];
            if (setCookie) {
              proxyRes.headers["set-cookie"] = setCookie.map((c) =>
                c.replace(/;\s*Secure/gi, ""),
              );
            }
          });
        },
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    target: "es2022",
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./tests/unit/setup.ts"],
    include: ["tests/unit/**/*.test.{ts,tsx}"],
    exclude: ["node_modules", "dist", "tests/e2e/**"],
    css: false,
  },
});
