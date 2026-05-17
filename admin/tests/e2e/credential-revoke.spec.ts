import { expect, test } from "@playwright/test";

/** F-3: 사고 대응 — credential revoke. M5에서 활성화. */
test.fixme("F-3: RP_ADMIN revokes a credential", async ({ page }) => {
  await page.goto("/");
  expect(true).toBe(true);
});
