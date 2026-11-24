// @ts-check
const { test, expect } = require("@playwright/test");
const { signIn } = require("./helpers");

// These tests start signed out.
test.use({ storageState: { cookies: [], origins: [] } });

test.describe("sign in", () => {
  test("the sign-in screen shows the logo, form and footer", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Welcome Back" })).toBeVisible();
    await expect(page.getByRole("img", { name: "Port Bridge" })).toBeVisible();
    await expect(page.getByPlaceholder("Enter admin password")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign In" })).toBeVisible();
    await expect(page.getByRole("link", { name: "nooblk" })).toHaveAttribute(
      "href",
      "https://github.com/nooblk-98",
    );
  });

  test("a wrong password is refused with a message", async ({ page }) => {
    await signIn(page, "not-the-password");
    await expect(page.getByText("Invalid password")).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
  });

  test("a blank password is refused", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: "Sign In" }).click();
    await expect(page).toHaveURL(/\/login/);
  });

  test("the right password opens the dashboard", async ({ page }) => {
    await signIn(page);
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("heading", { level: 2, name: "Dashboard" })).toBeVisible();
  });

  test("signed-out visitors are sent to sign in and back to the page they wanted", async ({ page }) => {
    await page.goto("/forwarding");
    await expect(page).toHaveURL(/\/login\?next=%2Fforwarding|\/login\?next=\/forwarding/);
    await signIn(page, undefined, { visit: false });
    await expect(page).toHaveURL(/\/forwarding$/);
    await expect(page.getByRole("heading", { level: 2, name: "Port Forwarding" })).toBeVisible();
  });

  test("the API refuses signed-out requests", async ({ request }) => {
    for (const path of ["/api/clients", "/api/stats", "/api/forwardings"]) {
      const response = await request.get(path, { maxRedirects: 0 });
      expect([401, 302, 303]).toContain(response.status());
    }
  });

  test("signing out ends the session", async ({ page }) => {
    await signIn(page);
    await expect(page.getByRole("heading", { level: 2, name: "Dashboard" })).toBeVisible();
    if ((page.viewportSize()?.width ?? 0) < 768) {
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await page.locator("#mobile-menu").getByRole("button", { name: "Sign Out" }).click();
    } else {
      await page.locator("aside").getByRole("button", { name: "Sign Out" }).click();
    }
    await expect(page).toHaveURL(/\/login/);
    await page.goto("/clients");
    await expect(page).toHaveURL(/\/login/);
  });
});
