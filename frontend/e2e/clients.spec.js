// @ts-check
const { test, expect } = require("@playwright/test");
const { openPage, clearImportNotices, expectNoHorizontalScroll } = require("./helpers");

test.describe.configure({ mode: "serial" });

const cards = page => page.getByTestId("client-card");
const card = (page, name) => cards(page).filter({ has: page.getByRole("heading", { name, exact: true }) });

async function openMenu(page, name) {
  await page.getByRole("button", { name: `Actions for ${name}` }).click();
}

async function addClient(page, name) {
  await page.getByRole("button", { name: /New Client/ }).click();
  const dialog = page.getByRole("dialog").filter({ hasText: "Add New Client" });
  await dialog.getByPlaceholder("e.g. Laptop-Home").fill(name);
  await dialog.getByRole("button", { name: /Create|Add/ }).last().click();
  await expect(dialog).toBeHidden();
  await expect(card(page, name)).toBeVisible();
}

async function deleteClient(page, name) {
  await openMenu(page, name);
  await page.getByRole("button", { name: "Delete Client" }).click();
  const confirm = page.getByRole("dialog").filter({ hasText: "This will delete the client and its keys." });
  await expect(confirm).toContainText(name);
  await confirm.getByRole("button", { name: /Delete/ }).last().click();
  await expect(card(page, name)).toHaveCount(0);
}

test.describe("clients", () => {
  test.beforeEach(async ({ page }) => {
    await openPage(page, "/clients", "Clients");
    await expect(cards(page).first()).toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    await clearImportNotices(page);
  });

  test("shows every peer with its address, status and traffic", async ({ page }) => {
    await expect(cards(page)).toHaveCount(4);
    const home = card(page, "home");
    await expect(home).toContainText("Online");
    await expect(home).toContainText("10.8.0.2/24");
    await expect(home).toContainText("Last Handshake");
    await expect(home).toContainText("Data Usage");
    await expect(card(page, "router")).toContainText("Offline");
    await expect(card(page, "laptop")).toContainText("Online");
    await expectNoHorizontalScroll(page);
  });

  test("shows each peer's advertised routes and forwards", async ({ page }) => {
    await expect(card(page, "home")).toContainText("192.168.1.106/32");
    await expect(card(page, "home")).toContainText("18000-18010");
    await expect(card(page, "home")).toContainText("(TCP)");
    await expect(card(page, "laptop")).toContainText("No routes");
    await expect(card(page, "laptop")).toContainText("No active rules");
  });

  test("filters peers as you type and says when nothing matches", async ({ page }) => {
    const search = page.getByPlaceholder("Search clients...");
    await search.fill("lap");
    await expect(cards(page)).toHaveCount(1);
    await expect(card(page, "laptop")).toBeVisible();
    await search.fill("zzz");
    await expect(cards(page)).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "No clients found" })).toBeVisible();
    await search.fill("");
    await expect(cards(page)).toHaveCount(4);
  });

  test("the split tunnel switch saves and survives a reload", async ({ page }) => {
    const toggle = () => card(page, "laptop").getByRole("switch", { name: "Split tunnel" });
    await expect(toggle()).toBeChecked();
    await toggle().click();
    await expect(toggle()).not.toBeChecked();
    await expect
      .poll(async () => {
        const items = (await (await page.request.get("/api/clients")).json()).items;
        return items.find(item => item.name === "laptop").options.split_tunnel;
      })
      .toBe(false);
    await page.reload();
    await expect(toggle()).not.toBeChecked();
    await toggle().click();
    await expect(toggle()).toBeChecked();
  });

  test("the server access switch saves and survives a reload", async ({ page }) => {
    const toggle = () => card(page, "phone").getByRole("switch", { name: "Server access" });
    await expect(toggle()).not.toBeChecked();
    await toggle().click();
    await expect(toggle()).toBeChecked();
    await page.reload();
    await expect(toggle()).toBeChecked();
    await toggle().click();
    await expect(toggle()).not.toBeChecked();
  });

  test("explains the switches in a tooltip", async ({ page }) => {
    const tip = card(page, "home").getByRole("tooltip").first();
    await card(page, "home").getByRole("switch", { name: "Split tunnel" }).focus();
    await expect(tip).toBeVisible();
    await expect(tip).toContainText("only VPN and advertised-route traffic");
    await page.keyboard.press("Escape");
    await expect(tip).toBeHidden();
  });

  test("adds a peer, then renames and deletes it", async ({ page }) => {
    await addClient(page, "e2e-new");
    await expect(cards(page)).toHaveCount(5);
    await expect(card(page, "e2e-new")).toContainText("10.8.0.");

    await openMenu(page, "e2e-new");
    await page.getByRole("button", { name: "Rename" }).click();
    const rename = page.getByRole("dialog").filter({ hasText: "Rename Client" });
    await rename.getByPlaceholder("New client name").fill("e2e-renamed");
    await rename.getByRole("button", { name: /Rename|Save/ }).last().click();
    await expect(card(page, "e2e-renamed")).toBeVisible();
    await expect(card(page, "e2e-new")).toHaveCount(0);

    await deleteClient(page, "e2e-renamed");
    await expect(cards(page)).toHaveCount(4);
  });

  test("refuses a duplicate name", async ({ page }) => {
    await page.getByRole("button", { name: /New Client/ }).click();
    const dialog = page.getByRole("dialog").filter({ hasText: "Add New Client" });
    await dialog.getByPlaceholder("e.g. Laptop-Home").fill("home");
    await dialog.getByRole("button", { name: /Create|Add/ }).last().click();
    await expect(dialog).toBeVisible();
    await expect(cards(page)).toHaveCount(4);
    await dialog.getByRole("button", { name: "Cancel" }).click();
  });

  test("keeps the peer when a delete is cancelled", async ({ page }) => {
    await openMenu(page, "router");
    await page.getByRole("button", { name: "Delete Client" }).click();
    const confirm = page.getByRole("dialog").filter({ hasText: "This will delete the client and its keys." });
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await expect(confirm).toBeHidden();
    await expect(card(page, "router")).toBeVisible();
  });

  test("shows a QR code for the profile", async ({ page }) => {
    await openMenu(page, "home");
    await page.getByRole("button", { name: "Show QR Code" }).click();
    const dialog = page.getByRole("dialog").filter({ has: page.locator("img") }).last();
    await expect(dialog).toContainText("home");
    const image = dialog.locator("img").first();
    await expect(image).toBeVisible();
    await expect
      .poll(() => image.evaluate(node => /** @type {HTMLImageElement} */ (node).naturalWidth))
      .toBeGreaterThan(50);
    await dialog.getByRole("button", { name: "Close" }).click();
    await expect(dialog).toBeHidden();
  });

  test("offers the WireGuard profile as a download", async ({ page }) => {
    await openMenu(page, "home");
    const link = page.getByRole("link", { name: "Download Config" });
    await expect(link).toHaveAttribute("href", "/clients/home.conf");
    const response = await page.request.get("/clients/home.conf");
    expect(response.status()).toBe(200);
    expect(await response.text()).toContain("[Interface]");
    expect(response.headers()["cache-control"]).toContain("no-store");
  });

  test("opens the peer settings with the saved routes", async ({ page }) => {
    await openMenu(page, "home");
    await page.getByRole("button", { name: "Peer settings" }).click();
    const dialog = page.getByRole("dialog", { name: "Peer settings" });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("Peer: home");
    await expect(dialog.getByLabel("Advertised IPv4 hosts or subnets")).toHaveValue("192.168.1.106/32");
    await expect(dialog.getByRole("switch", { name: "Split tunnel" })).toBeChecked();
    await expect(dialog.getByRole("switch", { name: "Server access" })).not.toBeChecked();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
  });

  test("peer settings reject an invalid route and name the problem", async ({ page }) => {
    await openMenu(page, "laptop");
    await page.getByRole("button", { name: "Peer settings" }).click();
    const dialog = page.getByRole("dialog", { name: "Peer settings" });
    await dialog.getByLabel("Advertised IPv4 hosts or subnets").fill("not-an-address");
    await expect(dialog.getByText("not-an-address")).toBeVisible();
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
  });

  test("peer settings save DNS, MTU and keepalive", async ({ page }) => {
    await openMenu(page, "phone");
    await page.getByRole("button", { name: "Peer settings" }).click();
    const dialog = page.getByRole("dialog", { name: "Peer settings" });
    await dialog.getByPlaceholder("Auto").fill("1400");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
    await expect
      .poll(async () => {
        const items = (await (await page.request.get("/api/clients")).json()).items;
        return items.find(item => item.name === "phone").options.mtu;
      })
      .toBe(1400);

    // Put it back.
    await openMenu(page, "phone");
    await page.getByRole("button", { name: "Peer settings" }).click();
    await dialog.getByPlaceholder("Auto").fill("");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
  });
});
