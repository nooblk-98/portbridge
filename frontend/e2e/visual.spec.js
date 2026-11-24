// @ts-check
// Screenshot comparison, used to prove a styling refactor changed nothing:
//   VISUAL=1 npx playwright test visual --update-snapshots   (on the old code)
//   VISUAL=1 npx playwright test visual                      (on the new code)
// Baselines are not committed: font rendering differs between machines.
const { test, expect } = require("@playwright/test");
const { isMobile, openPage, clearImportNotices } = require("./helpers");

test.skip(!process.env.VISUAL, "set VISUAL=1 to run the screenshot comparison");
test.describe.configure({ mode: "serial" });

const THEMES = ["light", "dark"];
const SHOT = { animations: "disabled", maxDiffPixelRatio: 0.002, threshold: 0.15 };

/** Parts of the page that change from minute to minute. */
const volatile = page => [
  page.getByText(/Just now|\d+[smhd] ago|Seen /),
  page.getByRole("region").filter({ hasText: "Load average" }),
  page.locator("canvas"),
];

async function shoot(page, name, { scrollMain = false } = {}) {
  await page.evaluate(() => document.fonts.ready);
  if (scrollMain) await page.locator("main").evaluate(node => node.scrollTo(0, node.scrollHeight));
  await page.waitForTimeout(600);
  await expect(page).toHaveScreenshot(`${name}.png`, { ...SHOT, mask: volatile(page) });
}

for (const theme of THEMES) {
  test.describe(`${theme} theme`, () => {
    test.beforeEach(async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme === "dark" ? "dark" : "light", reducedMotion: "reduce" });
    });

    test("dashboard", async ({ page }) => {
      await openPage(page, "/", "Dashboard");
      await shoot(page, `dashboard-top-${theme}`);
      await shoot(page, `dashboard-bottom-${theme}`, { scrollMain: true });
    });

    test("clients", async ({ page }) => {
      await openPage(page, "/clients", "Clients");
      await expect(page.getByTestId("client-card")).toHaveCount(4);
      await shoot(page, `clients-top-${theme}`);
      await shoot(page, `clients-bottom-${theme}`, { scrollMain: true });
    });

    test("routes", async ({ page }) => {
      await openPage(page, "/routes", "Route access");
      await expect(page.getByRole("heading", { level: 3, name: "Route status" })).toBeVisible();
      await shoot(page, `routes-${theme}`);
    });

    test("forwarding", async ({ page }) => {
      await openPage(page, "/forwarding", "Port Forwarding");
      await expect(page.getByTestId("forwarding-row")).toHaveCount(1);
      await shoot(page, `forwarding-${theme}`);
    });

    test("add client dialog", async ({ page }) => {
      await openPage(page, "/clients", "Clients");
      await page.getByRole("button", { name: /New Client/ }).click();
      await expect(page.getByRole("dialog").filter({ hasText: "Add New Client" })).toBeVisible();
      await shoot(page, `dialog-add-client-${theme}`);
    });

    test("add rule dialog", async ({ page }) => {
      await openPage(page, "/forwarding", "Port Forwarding");
      await page.getByRole("button", { name: /New Rule/ }).click();
      await expect(page.getByRole("dialog").filter({ hasText: "Add Forwarding Rule" })).toBeVisible();
      await shoot(page, `dialog-add-rule-${theme}`);
    });

    test("remove rule dialog", async ({ page }) => {
      await openPage(page, "/forwarding", "Port Forwarding");
      await page.getByRole("button", { name: /Remove forwarding rule/ }).click();
      await expect(page.getByRole("dialog").filter({ hasText: "Remove Forwarding Rule" })).toBeVisible();
      await shoot(page, `dialog-remove-rule-${theme}`);
    });

    test("peer settings dialog", async ({ page }) => {
      await openPage(page, "/clients", "Clients");
      await page.getByRole("button", { name: "Actions for home" }).click();
      await page.getByRole("button", { name: "Peer settings" }).click();
      const dialog = page.getByRole("dialog", { name: "Peer settings" });
      await expect(dialog).toBeVisible();
      await dialog.getByRole("radio", { name: "Selected peers" }).check();
      await shoot(page, `dialog-peer-settings-${theme}`);
      await dialog.getByRole("button", { name: "Cancel" }).click();
    });

    test("client menu and tooltip", async ({ page }) => {
      await openPage(page, "/clients", "Clients");
      await page.getByRole("button", { name: "Actions for laptop" }).click();
      await shoot(page, `clients-menu-${theme}`);
      await page.keyboard.press("Escape");
      await page.mouse.click(5, 5);
      await page.getByTestId("client-card").filter({ hasText: "home" }).getByRole("switch", { name: "Split tunnel" }).focus();
      await shoot(page, `clients-tooltip-${theme}`);
    });

    test("import notice", async ({ page }) => {
      // The notice is for peers that already exported their profile.
      await page.request.get("/clients/laptop.conf");
      await openPage(page, "/clients", "Clients");
      await page.getByRole("button", { name: "Actions for phone" }).click();
      await page.getByRole("button", { name: "Peer settings" }).click();
      const dialog = page.getByRole("dialog", { name: "Peer settings" });
      await dialog.getByLabel("Advertised IPv4 hosts or subnets").fill("192.168.77.0/24");
      await dialog.getByRole("button", { name: "Save" }).click();
      await expect(page.getByRole("status").filter({ hasText: "to import" })).toBeVisible();
      await shoot(page, `import-notice-${theme}`);
      await clearImportNotices(page);
      await page.getByRole("button", { name: "Actions for phone" }).click();
      await page.getByRole("button", { name: "Peer settings" }).click();
      await dialog.getByLabel("Advertised IPv4 hosts or subnets").fill("");
      await dialog.getByRole("button", { name: "Save" }).click();
      await expect(dialog).toBeHidden();
      await clearImportNotices(page);
    });

    test("mobile drawer", async ({ page }) => {
      test.skip(!isMobile(page), "phone only");
      await openPage(page, "/", "Dashboard");
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await expect(page.locator("#mobile-menu")).toBeVisible();
      await shoot(page, `drawer-${theme}`);
    });
  });
}

test.describe("signed out", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  for (const theme of THEMES) {
    test(`sign-in screen, ${theme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme === "dark" ? "dark" : "light" });
      await page.goto("/login");
      await shoot(page, `login-${theme}`);
    });
  }
});
