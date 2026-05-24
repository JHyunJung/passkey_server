import { expect, test } from "@playwright/test";

const ADMIN_EMAIL = process.env.PASSKEY_DEV_ADMIN_EMAIL ?? "dev@local.test";
const ADMIN_PASSWORD = process.env.PASSKEY_DEV_ADMIN_PASSWORD ?? "devpassword!";

/**
 * Both pages live under `RequirePlatformOperator` so an anonymous visit redirects
 * to login. After login as the PLATFORM_OPERATOR dev seed, the pages render and
 * expose their headline + metric/table labels.
 *
 * Requires the full local stack: `scripts/dev-up.sh -y` (Passkey server + Admin Vite).
 * If the stack is down, the tests will fail at the login redirect — that's the test's
 * expected dependency, mirroring the existing `auth.spec.ts` smoke contract.
 */

async function loginAsPlatformOperator(page: import("@playwright/test").Page) {
  await page.goto("/");
  // RootRedirect renders <LoginPage /> when no session is present.
  await expect(page.getByLabel("이메일")).toBeVisible();
  await page.getByLabel("이메일").fill(ADMIN_EMAIL);
  await page.getByLabel("비밀번호").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: /로그인|sign in/i }).click();
  // PLATFORM_OPERATOR home is /tenants
  await expect(page).toHaveURL(/\/tenants$/);
}

test.describe("Platform Activity page", () => {
  test("loads metrics + feed shell for PLATFORM_OPERATOR", async ({ page }) => {
    await loginAsPlatformOperator(page);
    await page.goto("/platform/activity");
    await expect(page.getByRole("heading", { name: "Activity" })).toBeVisible();
    // Four metric tiles
    await expect(page.getByText("활동 (24H)")).toBeVisible();
    await expect(page.getByText("운영 액션 (24H)")).toBeVisible();
    await expect(page.getByText("보안 이벤트 (24H)")).toBeVisible();
    await expect(page.getByText("평균 응답")).toBeVisible();
    // Filter tabs — exact match avoids collision with the "전체 tenant" chip below.
    await expect(page.getByRole("button", { name: "전체", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "운영 액션" })).toBeVisible();
    await expect(page.getByRole("button", { name: "보안 실패" })).toBeVisible();
  });
});

test.describe("Audit Chain Monitor page", () => {
  test("loads status + table for PLATFORM_OPERATOR", async ({ page }) => {
    await loginAsPlatformOperator(page);
    await page.goto("/platform/audit-chain");
    await expect(
      page.getByRole("heading", { name: "Audit Chain Monitor" }),
    ).toBeVisible();
    await expect(page.getByText("무결 / 전체")).toBeVisible();
    await expect(page.getByText("검증된 audit row")).toBeVisible();
    await expect(page.getByText("검증 주기")).toBeVisible();
    await expect(page.getByText("평균 chain 검증")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /전체 즉시 검증/ }),
    ).toBeVisible();
  });
});
