import { test, expect } from "@playwright/test";

test("empty app loads create screen", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "创建房间" })).toBeVisible();
  await expect(page.locator("body")).not.toContainText("unsafe-inline");
});
