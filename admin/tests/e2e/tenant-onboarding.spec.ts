import { expect, test } from "@playwright/test";

/**
 * F-1: 새 RP 온보딩.
 * TODO M5: wire docker-compose backend + seed PLATFORM_OPERATOR account, then enable.
 */
test.fixme("F-1: PLATFORM_OPERATOR creates tenant → WebAuthn → policy → api key", async ({
  page,
}) => {
  await page.goto("/");
  // 로그인 → /tenants → 신규 → WebAuthn 저장 → 정책 저장 → API key 발급
  expect(true).toBe(true);
});
