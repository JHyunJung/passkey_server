import { expect, test } from "@playwright/test";

/** F-4: 월간 무결성 보고서 — verify 결과 카드. M5에서 활성화. */
test.fixme("F-4: PLATFORM_OPERATOR runs monthly chain verification", async ({ page }) => {
  await page.goto("/");
  expect(true).toBe(true);
});
