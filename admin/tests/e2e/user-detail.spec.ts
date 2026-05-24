import { expect, test } from "@playwright/test";

/**
 * Admin UserDetailPage e2e: tab switching (URL query params) + Sessions tab logout-all confirm modal.
 *
 * Requires a seeded environment with at least one tenant that has at least one user with
 * one credential and one active refresh token. Phase 4 (Task 20-21) will run this in CI;
 * adjust E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD env vars to match the test fixture.
 */
test.describe("Admin · 사용자 상세 페이지", () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto("/");

    // Fill in login credentials from environment variables
    await page.getByLabel("이메일").fill(process.env.E2E_ADMIN_EMAIL ?? "ops@local");
    await page.getByLabel("비밀번호").fill(process.env.E2E_ADMIN_PASSWORD ?? "ChangeMe1!");

    // Submit login form
    await page.getByRole("button", { name: /로그인|Sign in/i }).click();

    // Wait for navigation to tenants list
    await page.waitForURL(/\/tenants/);
  });

  test("사용자 목록 → 상세 → Credentials/Sessions 탭 전환", async ({ page }) => {
    // Click into first tenant (navigate to tenant detail)
    const firstTenantLink = page.locator("a").filter({ hasText: /\w+/ }).first();
    await firstTenantLink.click();

    // Navigate to Users tab within the tenant
    await page.click('a[href*="/users"]');

    // Click into first user in the table
    const firstUserRow = page.locator("table tbody tr").first();
    await firstUserRow.click();

    // Verify default tab is Credentials
    const activeTab = page.locator('[role="tab"][aria-selected="true"]');
    await expect(activeTab).toContainText("Credentials");

    // Switch to Sessions tab
    const sessionsTab = page.locator('[role="tab"]:has-text("Sessions")');
    await sessionsTab.click();

    // Verify URL contains tab=sessions query parameter
    await expect(page).toHaveURL(/\?tab=sessions/);

    // Verify "활성만" toggle exists (Segmented control with active/all options)
    await expect(page.getByText("활성만")).toBeVisible();
  });

  test("Sessions 탭 — 모두 로그아웃 모달 표시 + 취소", async ({ page }) => {
    // Navigate to first tenant
    const firstTenantLink = page.locator("a").filter({ hasText: /\w+/ }).first();
    await firstTenantLink.click();

    // Navigate to Users tab
    await page.click('a[href*="/users"]');

    // Click into first user
    const firstUserRow = page.locator("table tbody tr").first();
    await firstUserRow.click();

    // Switch to Sessions tab
    const sessionsTab = page.locator('[role="tab"]:has-text("Sessions")');
    await sessionsTab.click();

    // Click "모두 로그아웃" button (destructive variant)
    const logoutAllButton = page.locator('button:has-text("모두 로그아웃")');
    await logoutAllButton.click();

    // Verify confirm modal is displayed with correct title
    const modalTitle = page.locator('[role="dialog"] [role="heading"]');
    await expect(modalTitle).toContainText("모든 세션 로그아웃");

    // Click cancel button to close modal without executing logout
    const cancelButton = page.locator('[role="dialog"] button:has-text("취소")');
    await cancelButton.click();

    // Verify modal is closed (title is no longer visible)
    await expect(page.locator('[role="dialog"]')).not.toBeVisible();
  });
});
