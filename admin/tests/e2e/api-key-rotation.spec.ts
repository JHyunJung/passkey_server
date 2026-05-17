import { expect, test } from "@playwright/test";

/** F-2: API key rotation — plaintext 모달 닫기 강제 검증 포함. M5에서 활성화. */
test.fixme("F-2: RP_ADMIN rotates API key", async ({ page }) => {
  await page.goto("/");
  expect(true).toBe(true);
});
