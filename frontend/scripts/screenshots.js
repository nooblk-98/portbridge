#!/usr/bin/env node
// Regenerates the README screenshots in images/screenshots/ from the demo server
// (examples/e2e_server.rs: fixture peers, nothing real). Run from frontend/:
//
//   npm run screenshots
//
// Needs the browser from `npx playwright install chromium` and a Rust toolchain.
// The pages are 1600 CSS pixels wide, saved at 2000 pixels (1.25x), as full
// pages: the window is resized to fit each page's content, so nothing scrolls.
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("@playwright/test");

const ROOT = path.join(__dirname, "../..");
const OUT = path.join(ROOT, "images/screenshots");
const PORT = process.env.E2E_PORT || "43290";
const BASE = `http://127.0.0.1:${PORT}`;
const WIDTH = 1600;
const SCALE = 2000 / WIDTH;

/** The newest released version in the changelog, shown in the footer instead of "0.0.0-dev". */
function latestVersion() {
  const text = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
  return /^## \[(\d+\.\d+\.\d+)\]/m.exec(text)?.[1] ?? "1.0.0";
}

/** Start the demo server and wait until it answers. Returns a function that stops it. */
async function startServer() {
  execFileSync("cargo", ["build", "--quiet", "--example", "e2e_server"], { cwd: ROOT, stdio: "inherit" });
  const server = spawn(path.join(ROOT, "target/debug/examples/e2e_server"), [], {
    cwd: ROOT,
    env: { ...process.env, E2E_PORT: PORT },
    stdio: "ignore",
  });
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      if ((await fetch(`${BASE}/login`)).ok) return () => server.kill();
    } catch {
      // Not listening yet.
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  server.kill();
  throw new Error("The demo server did not start.");
}

/** Resize the window so the whole page fits with no scrolling, then let the layout settle. */
async function fitToContent(page, contentSelector, extra = 0) {
  await page.setViewportSize({ width: WIDTH, height: 3000 });
  await page.waitForTimeout(300);
  const height = await page.evaluate(
    ([selector, padding]) => {
      const content = document.querySelector(selector);
      const footer = document.querySelector("footer");
      return Math.ceil(content.getBoundingClientRect().height + (footer?.offsetHeight ?? 0) + padding);
    },
    [contentSelector, extra],
  );
  await page.setViewportSize({ width: WIDTH, height });
  await page.waitForTimeout(700);
}

async function main() {
  const version = latestVersion();
  const stop = await startServer();
  const browser = await chromium.launch({ channel: "chromium" });
  try {
    for (const scheme of ["light", "dark"]) {
      const context = await browser.newContext({
        viewport: { width: WIDTH, height: 900 },
        deviceScaleFactor: SCALE,
        colorScheme: scheme,
      });
      const page = await context.newPage();
      // The demo server is a development build (0.0.0-dev), so answering with that
      // same number means "nothing newer", and no "update available" banner shows.
      await page.route("https://api.github.com/**", route =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            tag_name: "v0.0.0",
            html_url: "https://github.com/nooblk-98/portbridge/releases/tag/v0.0.0",
            body: "",
          }),
        }),
      );
      await page.goto(`${BASE}/login`);
      await page.getByPlaceholder("Enter admin password").fill("e2e-password");
      await page.getByRole("button", { name: "Sign In" }).click();
      await page.waitForURL(`${BASE}/`);

      /** Capture the current page, with the released version shown instead of "0.0.0-dev". */
      const shoot = async (file, heading, contentSelector = "main > div", extra = 0) => {
        await page.getByRole("heading", { level: 2, name: heading }).waitFor();
        await page.evaluate(label => {
          const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
          for (let node = walker.nextNode(); node; node = walker.nextNode()) {
            if (node.nodeValue.includes("0.0.0-dev")) node.nodeValue = node.nodeValue.replaceAll("0.0.0-dev", label);
          }
        }, version);
        await fitToContent(page, contentSelector, extra);
        await page.screenshot({ path: path.join(OUT, file) });
        console.log(`wrote ${path.relative(ROOT, path.join(OUT, file))}`);
      };

      if (scheme === "dark") {
        await page.goto(`${BASE}/`);
        await page.waitForLoadState("networkidle");
        await shoot("dashboard-dark.png", "Dashboard");
      } else {
        await page.goto(`${BASE}/`);
        await page.waitForLoadState("networkidle");
        await shoot("dashboard.png", "Dashboard");
        await page.goto(`${BASE}/clients`);
        await page.getByTestId("client-card").first().waitFor();
        await shoot("clients.png", "Clients");
        await page.goto(`${BASE}/routes`);
        await page.getByRole("heading", { level: 3, name: "Route status" }).waitFor();
        await shoot("routes.png", "Route access");
        await page.goto(`${BASE}/forwarding`);
        await page.getByTestId("forwarding-row").first().waitFor();
        await shoot("forwarding.png", "Port Forwarding");

        // Peer settings: open the dialog for the peer that advertises a route.
        await page.goto(`${BASE}/clients`);
        await page.getByTestId("client-card").first().waitFor();
        await page.getByRole("button", { name: "Actions for home" }).click();
        await page.getByRole("button", { name: "Peer settings" }).click();
        await page.getByRole("dialog", { name: "Peer settings" }).waitFor();
        // The dialog sits in an overlay with 32px of padding above and below it.
        await shoot("peer-settings.png", "Clients", '[aria-labelledby="peer-settings-title"] form', 64);
      }
      await context.close();
    }
  } finally {
    await browser.close();
    stop();
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
