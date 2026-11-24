// @ts-check
const { test: setup, expect } = require("@playwright/test");
const { signIn } = require("./helpers");

// Sign in once through the real form and reuse the session in the other specs.
setup("sign in", async ({ page }) => {
  await signIn(page);
  await expect(page.getByRole("heading", { level: 2, name: "Dashboard" })).toBeVisible();
  await page.context().storageState({ path: "e2e/.auth/session.json" });
});
