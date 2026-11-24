// @ts-check
const { test, expect } = require("@playwright/test");
const { openPage, expectNoHorizontalScroll } = require("./helpers");

test.describe.configure({ mode: "serial" });

const rows = page => page.getByTestId("forwarding-row");

async function openRuleDialog(page) {
  await page.getByRole("button", { name: /New Rule/ }).click();
  const dialog = page.getByRole("dialog").filter({ hasText: "Add Forwarding Rule" });
  await expect(dialog).toBeVisible();
  return dialog;
}

async function removeRule(page, port) {
  await page.getByRole("button", { name: `Remove forwarding rule for port ${port}` }).click();
  const confirm = page.getByRole("dialog").filter({ hasText: "Remove Forwarding Rule" });
  await expect(confirm).toContainText(port);
  await confirm.getByRole("button", { name: "Remove" }).click();
}

test.describe("forwarding", () => {
  test.beforeEach(async ({ page }) => {
    await openPage(page, "/forwarding", "Port Forwarding");
  });

  test("lists the existing rule with protocol, ports and target peer", async ({ page }) => {
    await expect(rows(page)).toHaveCount(1);
    const row = rows(page).first();
    await expect(row).toContainText(/tcp/i);
    await expect(row).toContainText("18000-18010");
    await expect(row).toContainText("home");
    await expect(row).toContainText("10.8.0.2");
    await expectNoHorizontalScroll(page);
  });

  test("the add dialog lists the protocols and every peer", async ({ page }) => {
    const dialog = await openRuleDialog(page);
    await expect(dialog.getByPlaceholder("20000 or 8000-8100")).toBeVisible();
    const protocol = dialog.locator("select").first();
    await expect(protocol.locator("option")).toHaveText(["TCP & UDP", "TCP Only", "UDP Only"]);
    const target = dialog.locator("select").nth(1);
    await expect(target.locator("option")).toHaveText([
      "Select a client",
      "home (10.8.0.2)",
      "laptop (10.8.0.3)",
      "phone (10.8.0.4)",
      "router (10.8.0.5)",
    ]);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
  });

  test("adds a rule, uses the public port when the internal port is blank, then removes it", async ({ page }) => {
    const dialog = await openRuleDialog(page);
    await dialog.getByPlaceholder("20000 or 8000-8100").fill("30000");
    await dialog.locator("select").nth(1).selectOption({ label: "laptop (10.8.0.3)" });
    await dialog.getByRole("button", { name: "Add Rule" }).click();
    await expect(dialog).toBeHidden();

    await expect(rows(page)).toHaveCount(2);
    const added = rows(page).filter({ hasText: "30000" });
    await expect(added).toContainText("laptop");
    await expect(added).toContainText(/both/i);

    const saved = await page.request.get("/api/forwardings");
    const items = (await saved.json()).items;
    const rule = items.find(item => String(item.port) === "30000");
    expect(rule).toMatchObject({ client_ip: "10.8.0.3", protocol: "both", target_port: 30000 });

    await removeRule(page, "30000");
    await expect(rows(page)).toHaveCount(1);
    const after = await (await page.request.get("/api/forwardings")).json();
    expect(after.items.map(item => String(item.port))).toEqual(["18000-18010"]);
  });

  test("keeps an explicit internal port and a protocol choice", async ({ page }) => {
    const dialog = await openRuleDialog(page);
    await dialog.getByPlaceholder("20000 or 8000-8100").fill("30001");
    await dialog.getByPlaceholder("Same as public (Optional)").fill("8080");
    await dialog.locator("select").first().selectOption("udp");
    await dialog.locator("select").nth(1).selectOption({ label: "phone (10.8.0.4)" });
    await dialog.getByRole("button", { name: "Add Rule" }).click();
    const added = rows(page).filter({ hasText: "30001" });
    await expect(added).toContainText("8080");
    await expect(added).toContainText(/udp/i);
    await removeRule(page, "30001");
    await expect(rows(page)).toHaveCount(1);
  });

  test("the new rule also shows on the peer's card", async ({ page }) => {
    const dialog = await openRuleDialog(page);
    await dialog.getByPlaceholder("20000 or 8000-8100").fill("30002");
    await dialog.locator("select").nth(1).selectOption({ label: "phone (10.8.0.4)" });
    await dialog.getByRole("button", { name: "Add Rule" }).click();
    await expect(rows(page).filter({ hasText: "30002" })).toBeVisible();

    await openPage(page, "/clients", "Clients");
    const card = page.getByTestId("client-card").filter({ hasText: "phone" });
    await expect(card).toContainText("30002");

    await openPage(page, "/forwarding", "Port Forwarding");
    await removeRule(page, "30002");
    await expect(rows(page)).toHaveCount(1);
  });

  test("refuses an invalid port and keeps the dialog open", async ({ page }) => {
    const dialog = await openRuleDialog(page);
    await dialog.getByPlaceholder("20000 or 8000-8100").fill("not-a-port");
    await dialog.locator("select").nth(1).selectOption({ label: "home (10.8.0.2)" });
    await dialog.getByRole("button", { name: "Add Rule" }).click();
    await expect(dialog).toBeVisible();
    await expect(rows(page)).toHaveCount(1);
    await dialog.getByRole("button", { name: "Cancel" }).click();
  });

  test("asks before removing and keeps the rule when cancelled", async ({ page }) => {
    await page.getByRole("button", { name: "Remove forwarding rule for port 18000-18010" }).click();
    const confirm = page.getByRole("dialog").filter({ hasText: "Remove Forwarding Rule" });
    await expect(confirm).toBeVisible();
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await expect(confirm).toBeHidden();
    await expect(rows(page)).toHaveCount(1);
  });
});
