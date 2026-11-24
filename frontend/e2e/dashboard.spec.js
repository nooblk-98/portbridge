// @ts-check
const { test, expect } = require("./fixtures");
const { openPage, isMobile } = require("./helpers");

test.describe("dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await openPage(page, "/", "Dashboard");
  });

  test("shows the headline numbers and network settings", async ({ page }) => {
    await expect(page.getByText("Total Clients")).toBeVisible();
    await expect(page.getByRole("heading", { level: 3, name: "4", exact: true })).toBeVisible();
    await expect(page.getByText("Active Ports")).toBeVisible();
    await expect(page.getByRole("heading", { level: 3, name: "1", exact: true })).toBeVisible();
    await expect(page.getByText("Network Configuration")).toBeVisible();
    await expect(page.getByText("10.8.0.0/24")).toBeVisible();
    await expect(page.getByText("wg0", { exact: true }).first()).toBeVisible();
  });

  test("lists every peer with who is online", async ({ page }) => {
    const panel = page.getByRole("region").filter({ hasText: "Peers online" });
    await expect(panel.getByRole("img", { name: "3 of 4 peers online" })).toBeVisible();
    for (const name of ["home", "laptop", "phone", "router"]) {
      await expect(panel.getByText(name, { exact: true })).toBeVisible();
    }
    await expect(panel.getByText("Connected")).toHaveCount(3);
    await expect(panel.getByText(/^Seen /)).toHaveCount(1);
  });

  test("totals the traffic and splits it into download and upload", async ({ page }) => {
    const panel = page.getByRole("region").filter({ hasText: "Total traffic" });
    await expect(panel.getByText("Download").first()).toBeVisible();
    await expect(panel.getByText("Upload").first()).toBeVisible();
    await expect(panel.getByText(/Last 24 h:/)).toHaveCount(2);
    await expect(panel.getByRole("img", { name: /Download \d+ percent, upload \d+ percent/ })).toBeVisible();
    await expect(panel.getByText("Collecting data")).toBeHidden();
  });

  test("reports connection health check by check", async ({ page }) => {
    const panel = page.getByRole("region").filter({ hasText: "Connection health" });
    await expect(panel.getByText("Healthy")).toBeVisible();
    for (const check of [
      "WireGuard interface",
      "WireGuard port",
      "Peers",
      "Firewall rules",
      "Internet access",
    ]) {
      await expect(panel.getByText(check, { exact: true })).toBeVisible();
    }
    await expect(panel.getByText("3 of 4 online")).toBeVisible();
    await expect(panel.getByText("Listening on UDP 51820")).toBeVisible();
  });

  test("draws the traffic chart and switches its time range", async ({ page }) => {
    const panel = page.getByRole("region").filter({ hasText: "Traffic over time" });
    await expect(panel.getByRole("img", { name: /traffic over the selected period/ })).toBeVisible();
    await expect(panel.getByText("No traffic recorded")).toBeHidden();
    const ranges = panel.getByRole("group", { name: "Time range" });
    await expect(ranges.getByRole("button", { name: "1 h" })).toHaveAttribute("aria-pressed", "true");
    for (const range of ["24 h", "7 d", "1 h"]) {
      await ranges.getByRole("button", { name: range }).click();
      await expect(ranges.getByRole("button", { name: range })).toHaveAttribute("aria-pressed", "true");
    }
    const canvasSize = await panel.locator("canvas").evaluate(node => [node.width, node.height]);
    expect(canvasSize[0]).toBeGreaterThan(100);
    expect(canvasSize[1]).toBeGreaterThan(50);
  });

  test("the chart stays drawn, in the right colours, when the theme is switched", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await openPage(page, "/", "Dashboard");
    const canvas = page.getByRole("img", { name: /traffic over the selected period/ });
    await expect(canvas).toBeVisible();

    /** What the chart looks like right now: visible, sized, painted, and its axis colour. */
    const chart = () =>
      canvas.evaluate(node => {
        const box = node.getBoundingClientRect();
        const data = /** @type {CanvasRenderingContext2D} */ (node.getContext("2d")).getImageData(0, 0, node.width, node.height).data;
        let painted = 0;
        for (let index = 3; index < data.length; index += 4) if (data[index]) painted += 1;
        // @ts-ignore Chart is the Chart.js global.
        const drawing = window.Chart.getChart(node);
        return {
          shown: getComputedStyle(node).display !== "none" && box.width > 100 && box.height > 50,
          painted: painted > 1000,
          axis: drawing.options.scales.x.ticks.color,
        };
      });

    const switchTheme = async label => {
      if (isMobile(page)) {
        await page.getByRole("button", { name: "Open navigation menu" }).click();
        await page.locator("#mobile-menu").getByRole("button", { name: label }).click();
        await page.mouse.click(370, 400);
      } else {
        await page.locator("aside").getByRole("button", { name: label }).click();
      }
    };

    expect(await chart()).toEqual({ shown: true, painted: true, axis: "#64748b" });
    await switchTheme("Dark Mode");
    await expect.poll(chart).toEqual({ shown: true, painted: true, axis: "#94a3b8" });
    await switchTheme("Light Mode");
    await expect.poll(chart).toEqual({ shown: true, painted: true, axis: "#64748b" });
  });

  test("ranks the busiest peers", async ({ page }) => {
    const panel = page.getByRole("region").filter({ hasText: "Top talkers" });
    await expect(panel.getByText("No traffic recorded")).toBeHidden();
    await expect(panel.getByRole("listitem")).toHaveCount(4);
    await expect(panel.getByRole("listitem").first()).toContainText("router");
  });

  test("shows the server's CPU, memory, disk and load", async ({ page }) => {
    const panel = page.getByRole("region").filter({ hasText: "Load average" });
    for (const name of ["CPU", "Memory", "Disk"]) {
      await expect(panel.getByRole("img", { name: new RegExp(`^${name} \\d+ percent`) })).toBeVisible();
    }
    for (const window of ["1 min", "5 min", "15 min"]) {
      await expect(panel.getByText(window, { exact: true })).toBeVisible();
    }
  });

  test("the quick actions open the add-client and add-rule dialogs", async ({ page }) => {
    await page.getByRole("button", { name: /Add New Client/ }).click();
    const addClient = page.getByRole("dialog").filter({ hasText: "Add New Client" });
    await expect(addClient).toBeVisible();
    await addClient.getByRole("button", { name: "Cancel" }).click();
    await expect(addClient).toBeHidden();

    await page.getByRole("button", { name: /Open Port/ }).click();
    const addRule = page.getByRole("dialog").filter({ hasText: "Add Forwarding Rule" });
    await expect(addRule).toBeVisible();
    await addRule.getByRole("button", { name: "Cancel" }).click();
    await expect(addRule).toBeHidden();
  });
});
