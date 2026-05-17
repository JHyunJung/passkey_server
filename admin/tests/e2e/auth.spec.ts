import { expect, test } from "@playwright/test";

// Smoke spec. Full F-1~F-4 flows require seeded admin users + running backend; left as TODO.
test.describe("auth", () => {
  test("login page renders", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Crosscert Passkey Admin" })).toBeVisible();
    await expect(page.getByLabel("이메일")).toBeVisible();
    await expect(page.getByLabel("비밀번호")).toBeVisible();
  });
});
