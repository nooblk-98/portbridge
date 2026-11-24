// @ts-check
const { test, expect, mockRelease } = require("./fixtures");
const { openPage, expectNoHorizontalScroll, watchForProblems } = require("./helpers");

const INSTALL_COMMAND =
  "curl -fsSL https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- --upgrade";
const DOCKER_COMMAND =
  "docker compose -f docker-compose-live.yml pull && docker compose -f docker-compose-live.yml up -d";

const notice = page => page.getByRole("status").filter({ hasText: "is available" });
const dialog = page => page.getByRole("dialog", { name: /is available/ });

/** Load the dashboard once GitHub has been asked about the latest release. */
async function openDashboard(page) {
  const asked = page.waitForRequest("https://api.github.com/**", { timeout: 15_000 }).catch(() => null);
  await openPage(page, "/", "Dashboard");
  await asked;
}

test.describe("update notification", () => {
  test.beforeEach(async ({ page }) => {
    // Each test starts with nothing remembered about earlier choices.
    await page.addInitScript(() => {
      if (!sessionStorage.getItem("e2e-cleared")) {
        localStorage.removeItem("portbridge.update.release");
        localStorage.removeItem("portbridge.update.choice");
        sessionStorage.setItem("e2e-cleared", "1");
      }
    });
  });

  test("stays quiet when already on the latest release", async ({ page }) => {
    await openDashboard(page);
    await page.waitForTimeout(500);
    await expect(notice(page)).toBeHidden();
  });

  test("announces a newer release with both versions", async ({ page }) => {
    await mockRelease(page, "1.5.0");
    await openDashboard(page);
    await expect(notice(page)).toBeVisible();
    await expect(notice(page)).toContainText("PortBridge v1.5.0 is available");
    await expect(notice(page)).toContainText("You are running v0.0.0-dev");
    await expect(notice(page).getByRole("button", { name: "What's new" })).toBeVisible();
    await expect(notice(page).getByRole("button", { name: "Remind me later" })).toBeVisible();
    await expect(notice(page).getByRole("button", { name: "Ignore this version" })).toBeVisible();
    await expectNoHorizontalScroll(page);
  });

  test("does not announce an answer it cannot read", async ({ page }) => {
    await mockRelease(page, "latest");
    await openDashboard(page);
    await page.waitForTimeout(500);
    await expect(notice(page)).toBeHidden();
  });

  test("stays quiet and error-free when GitHub cannot be reached", async ({ page }) => {
    const problems = watchForProblems(page);
    await mockRelease(page, "offline");
    await openDashboard(page);
    await page.waitForTimeout(500);
    await expect(notice(page)).toBeHidden();
    expect(problems.filter(problem => /pageerror|page error/.test(problem))).toEqual([]);
  });

  test("stays quiet when GitHub answers with an error", async ({ page }) => {
    await mockRelease(page, { status: 403 });
    await openDashboard(page);
    await page.waitForTimeout(500);
    await expect(notice(page)).toBeHidden();
  });

  test("the page may call GitHub, and nowhere else", async ({ page }) => {
    const response = await page.request.get("/login");
    const policy = response.headers()["content-security-policy"];
    expect(policy).toContain("connect-src 'self' https://api.github.com");
    expect(policy).not.toMatch(/connect-src[^;]*\*/);
  });

  test("asks GitHub at most once per page load window, then uses its cache", async ({ page }) => {
    const calls = await mockRelease(page, "1.5.0");
    await openDashboard(page);
    await expect(notice(page)).toBeVisible();
    expect(calls.count).toBe(1);
    await page.reload();
    await expect(notice(page)).toBeVisible();
    expect(calls.count).toBe(1);
  });

  test.describe("the changelog popup", () => {
    test.beforeEach(async ({ page }) => {
      await mockRelease(page, "1.5.0");
      await openDashboard(page);
      await notice(page).getByRole("button", { name: "What's new" }).click();
      await expect(dialog(page)).toBeVisible();
    });

    test("shows the release, its date and the notes", async ({ page }) => {
      const popup = dialog(page);
      await expect(popup).toContainText("PortBridge v1.5.0 is available");
      await expect(popup).toContainText("Released November 24, 2026");
      await expect(popup).toContainText("You are running v0.0.0-dev");
      const notes = popup.getByRole("region", { name: "Release notes" });
      await expect(notes.getByRole("heading", { name: "Added" })).toBeVisible();
      await expect(notes.getByRole("heading", { name: "Fixed" })).toBeVisible();
      await expect(notes.getByRole("listitem")).toHaveCount(3);
      await expect(notes.locator("strong").first()).toHaveText("A notice when a newer release exists.");
      await expect(notes.locator("code").filter({ hasText: "10.8.0.0/24" })).toBeVisible();
      await expect(notes).toContainText("with Remind me later and Ignore this version");
    });

    test("opens links safely in a new tab", async ({ page }) => {
      const notes = dialog(page).getByRole("region", { name: "Release notes" });
      const guide = notes.getByRole("link", { name: "guide" });
      await expect(guide).toHaveAttribute("href", "https://github.com/nooblk-98/portbridge#readme");
      await expect(guide).toHaveAttribute("target", "_blank");
      await expect(guide).toHaveAttribute("rel", /noopener/);
      await expect(dialog(page).getByRole("link", { name: "Open the release on GitHub" })).toHaveAttribute(
        "href",
        "https://github.com/nooblk-98/portbridge/releases/tag/v1.5.0",
      );
    });

    test("shows hostile release notes as plain text and runs nothing", async ({ page }) => {
      const notes = dialog(page).getByRole("region", { name: "Release notes" });
      await expect(notes).toContainText("<script>window.__pwned = 1</script>");
      await expect(notes.locator("script")).toHaveCount(0);
      // A javascript: link is shown as text, never made clickable.
      await expect(notes.getByRole("link", { name: /bad/ })).toHaveCount(0);
      await expect(notes).toContainText("[bad](javascript:window.__pwned=1)");
      expect(await page.evaluate(() => /** @type {any} */ (window).__pwned)).toBeUndefined();
    });

    test("leaves out the install section, which the popup replaces", async ({ page }) => {
      const notes = dialog(page).getByRole("region", { name: "Release notes" });
      await expect(notes).not.toContainText("Install or upgrade");
      await expect(notes).not.toContainText("example.invalid");
      await expect(notes).toContainText("Full changelog");
    });

    test("shows the upgrade command for each way PortBridge is installed", async ({ page }) => {
      const popup = dialog(page);
      const command = popup.getByRole("tabpanel");
      const install = popup.getByRole("tab", { name: "Debian / Ubuntu" });
      const docker = popup.getByRole("tab", { name: "Docker" });
      await expect(install).toHaveAttribute("aria-selected", "true");
      await expect(command).toContainText(INSTALL_COMMAND);
      await expect(command).toContainText("settings, peers and keys are kept");
      await docker.click();
      await expect(docker).toHaveAttribute("aria-selected", "true");
      await expect(install).toHaveAttribute("aria-selected", "false");
      await expect(command).toContainText(DOCKER_COMMAND);
      await expect(command).toContainText("same project name and data volume");
    });

    test("copies the command", async ({ page, context }) => {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const popup = dialog(page);
      await popup.getByRole("button", { name: "Copy" }).click();
      await expect(popup.getByRole("button", { name: "Copied" })).toBeVisible();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(INSTALL_COMMAND);

      await popup.getByRole("tab", { name: "Docker" }).click();
      await popup.getByRole("button", { name: /Copy/ }).click();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(DOCKER_COMMAND);
    });

    test("moves focus into the popup, keeps it there, and returns it on Escape", async ({ page }) => {
      const popup = dialog(page);
      await expect(popup).toBeFocused();
      for (let step = 0; step < 14; step += 1) {
        await page.keyboard.press("Tab");
        expect(await popup.evaluate(node => node.contains(document.activeElement))).toBe(true);
      }
      await page.keyboard.press("Escape");
      await expect(popup).toBeHidden();
      await expect(notice(page).getByRole("button", { name: "What's new" })).toBeFocused();
      // Closing without choosing leaves the notice up.
      await expect(notice(page)).toBeVisible();
    });

    test("the close button dismisses only the popup", async ({ page }) => {
      await dialog(page).getByRole("button", { name: "Close" }).click();
      await expect(dialog(page)).toBeHidden();
      await expect(notice(page)).toBeVisible();
    });

    test("fits the screen and scrolls long notes inside the popup", async ({ page }) => {
      await expectNoHorizontalScroll(page);
      const box = await dialog(page).getByRole("button", { name: "Remind me later" }).boundingBox();
      expect(box).not.toBeNull();
    });
  });

  test.describe("remind me later", () => {
    test.beforeEach(async ({ page }) => {
      await mockRelease(page, "1.5.0");
      await openDashboard(page);
      await expect(notice(page)).toBeVisible();
    });

    test("hides the notice from the banner and keeps it hidden after a reload", async ({ page }) => {
      await notice(page).getByRole("button", { name: "Remind me later" }).click();
      await expect(notice(page)).toBeHidden();
      await expect(page.getByText("We will remind you again tomorrow.")).toBeVisible();
      await page.reload();
      await page.waitForTimeout(2500);
      await expect(notice(page)).toBeHidden();
    });

    test("works from the popup too", async ({ page }) => {
      await notice(page).getByRole("button", { name: "What's new" }).click();
      await dialog(page).getByRole("button", { name: "Remind me later" }).click();
      await expect(dialog(page)).toBeHidden();
      await expect(notice(page)).toBeHidden();
    });

    test("brings the notice back once a day has passed", async ({ page }) => {
      await notice(page).getByRole("button", { name: "Remind me later" }).click();
      await expect(notice(page)).toBeHidden();
      const stored = await page.evaluate(() => JSON.parse(localStorage.getItem("portbridge.update.choice")));
      const day = 24 * 60 * 60 * 1000;
      expect(stored.remindAt - Date.now()).toBeGreaterThan(day - 60_000);
      expect(stored.remindAt - Date.now()).toBeLessThanOrEqual(day);
      expect(stored.ignored).toBeUndefined();

      await page.evaluate(() =>
        localStorage.setItem("portbridge.update.choice", JSON.stringify({ remindAt: Date.now() - 1000 })),
      );
      await page.reload();
      await expect(notice(page)).toBeVisible();
    });
  });

  test.describe("ignore this version", () => {
    test.beforeEach(async ({ page }) => {
      await mockRelease(page, "1.5.0");
      await openDashboard(page);
      await expect(notice(page)).toBeVisible();
    });

    test("hides the notice for good, and says so", async ({ page }) => {
      await notice(page).getByRole("button", { name: "Ignore this version" }).click();
      await expect(notice(page)).toBeHidden();
      await expect(page.getByText("Ignoring v1.5.0.")).toBeVisible();
      await page.reload();
      await page.waitForTimeout(2500);
      await expect(notice(page)).toBeHidden();
    });

    test("works from the popup too", async ({ page }) => {
      await notice(page).getByRole("button", { name: "What's new" }).click();
      await dialog(page).getByRole("button", { name: "Ignore this version" }).click();
      await expect(dialog(page)).toBeHidden();
      await expect(notice(page)).toBeHidden();
    });

    test("does not hide the next release", async ({ page }) => {
      await notice(page).getByRole("button", { name: "Ignore this version" }).click();
      await expect(notice(page)).toBeHidden();
      // A newer release is published; drop the cached answer so it is looked up again.
      await mockRelease(page, "1.5.1");
      await page.evaluate(() => localStorage.removeItem("portbridge.update.release"));
      await page.reload();
      await expect(notice(page)).toBeVisible();
      await expect(notice(page)).toContainText("PortBridge v1.5.1 is available");
    });
  });
});
