// @ts-check
const { test, expect } = require("@playwright/test");
const { openPage, clearImportNotices, expectNoHorizontalScroll } = require("./helpers");

test.describe.configure({ mode: "serial" });

const ROUTE = "192.168.1.106/32";
const summary = (page, label) => page.getByRole("term").filter({ hasText: label }).locator("xpath=following-sibling::dd[1]");

async function openAccessDialog(page) {
  await page.getByRole("button", { name: `Edit access for route ${ROUTE} on home` }).click();
  const dialog = page.getByRole("dialog", { name: "Peer settings" });
  await expect(dialog).toBeVisible();
  return dialog;
}

test.describe("routes", () => {
  test.beforeEach(async ({ page }) => {
    await openPage(page, "/routes", "Route access");
    await expect(page.getByRole("heading", { level: 3, name: "Route status" })).toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    await clearImportNotices(page);
  });

  test("summarises the routes", async ({ page }) => {
    await expect(summary(page, "Advertised routes")).toHaveText("1");
    await expect(summary(page, "Selected peers only")).toHaveText("0");
    await expect(summary(page, "Blocked")).toHaveText("0");
    await expect(summary(page, "Profiles to export")).toHaveText("0");
    await expectNoHorizontalScroll(page);
  });

  test("lists each route with its owner and who may use it", async ({ page }) => {
    const region = page.getByRole("region").filter({ hasText: "Route status" });
    await expect(region.getByText(ROUTE, { exact: true }).locator("visible=true").first()).toBeVisible();
    await expect(region).toContainText("home");
    await expect(region).toContainText("Online");
    await expect(region).toContainText("All peers");
    await expect(region).toContainText("Every connected peer may use this route.");
  });

  test("lists every split-tunnel profile and records an export when it is downloaded", async ({ page }) => {
    const region = page.getByRole("region").filter({ hasText: "Split-tunnel profiles" });
    for (const name of ["home", "laptop", "phone", "router"]) {
      await expect(region.getByText(name, { exact: true })).toBeVisible();
    }
    const status = region.getByRole("listitem").filter({ hasText: "laptop" });
    await expect(status).toContainText(/No export recorded|Current profile exported/);

    // A download is the only thing that records an export.
    const download = await page.request.get("/clients/laptop.conf");
    expect(download.status()).toBe(200);
    await page.reload();
    await expect(
      page.getByRole("region").filter({ hasText: "Split-tunnel profiles" }).getByRole("listitem").filter({ hasText: "laptop" }),
    ).toContainText("Current profile exported");
  });

  test("refreshing reloads the data", async ({ page }) => {
    const refreshed = page.waitForResponse(response => response.url().endsWith("/api/clients"));
    await page.getByRole("button", { name: "Refresh" }).click();
    await refreshed;
    await expect(summary(page, "Advertised routes")).toHaveText("1");
  });

  test("restricting a route to no peers blocks it, then restoring reopens it", async ({ page }) => {
    let dialog = await openAccessDialog(page);
    await dialog.getByRole("radio", { name: "Selected peers" }).check();
    await expect(dialog.getByText("No peers selected, so this route is blocked for everyone.")).toBeVisible();
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();

    await expect(summary(page, "Blocked")).toHaveText("1");
    await expect(summary(page, "Selected peers only")).toHaveText("0");
    await expect(page.getByRole("region").filter({ hasText: "Route status" })).toContainText("Blocked");

    dialog = await openAccessDialog(page);
    await dialog.getByRole("radio", { name: "All peers" }).check();
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
    await expect(summary(page, "Blocked")).toHaveText("0");
  });

  test("allowing one peer is a restricted route, and it is saved", async ({ page }) => {
    let dialog = await openAccessDialog(page);
    await dialog.getByRole("radio", { name: "Selected peers" }).check();
    await dialog.getByRole("checkbox", { name: "laptop" }).check();
    await expect(dialog.getByText("No peers selected")).toBeHidden();
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
    await expect(summary(page, "Selected peers only")).toHaveText("1");
    await expect(summary(page, "Blocked")).toHaveText("0");

    await page.reload();
    await expect(summary(page, "Selected peers only")).toHaveText("1");

    dialog = await openAccessDialog(page);
    await expect(dialog.getByRole("radio", { name: "Selected peers" })).toBeChecked();
    await expect(dialog.getByRole("checkbox", { name: "laptop" })).toBeChecked();
    await dialog.getByRole("radio", { name: "All peers" }).check();
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
    await expect(summary(page, "Selected peers only")).toHaveText("0");
  });

  test("advertising a new route tells the other peers to import their profiles", async ({ page }) => {
    // The notice is for peers that already exported their profile.
    await page.request.get("/clients/laptop.conf");
    await openPage(page, "/clients", "Clients");
    await page.getByRole("button", { name: "Actions for phone" }).click();
    await page.getByRole("button", { name: "Peer settings" }).click();
    const dialog = page.getByRole("dialog", { name: "Peer settings" });
    await dialog.getByLabel("Advertised IPv4 hosts or subnets").fill("192.168.77.0/24");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();

    const banner = page.getByRole("status").filter({ hasText: "to import" });
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("192.168.77.0/24");
    await expect(banner.getByRole("link", { name: /Download profile for/ }).first()).toHaveAttribute(
      "href",
      /\/clients\/.+\.conf$/,
    );
    await clearImportNotices(page);
    await expect(banner).toBeHidden();

    // Remove the route again.
    await page.getByRole("button", { name: "Actions for phone" }).click();
    await page.getByRole("button", { name: "Peer settings" }).click();
    await dialog.getByLabel("Advertised IPv4 hosts or subnets").fill("");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
  });
});
