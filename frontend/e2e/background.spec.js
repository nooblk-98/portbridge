// @ts-check
const { test, expect } = require("./fixtures");
const { openPage, averageColor, watchForProblems } = require("./helpers");

const luminance = ([r, g, b]) => (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
// A strip of the page that is sky at any width: the gutter at the right edge, beside the cards.
const corner = page => ({ x: (page.viewportSize()?.width ?? 1280) - 10, y: 100, width: 8, height: 200 });
const sky = page => page.getByTestId("background");

/** How many elements in the sky run each animation, and whether they are visible. */
const animations = page =>
  sky(page).evaluate(node => {
    const counts = {};
    for (const element of node.querySelectorAll("*")) {
      const css = getComputedStyle(element);
      if (css.animationName === "none") continue;
      // A hidden parent takes its streak out of the layout, so it has no box at all.
      const key = `${css.animationName}:${element.getClientRects().length === 0 ? "hidden" : "shown"}`;
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  });

test.describe("falling stars background", () => {
  test("is a decorative layer behind the page that never blocks clicks", async ({ page }) => {
    const problems = watchForProblems(page);
    await openPage(page, "/", "Dashboard");
    await expect(sky(page)).toHaveCount(1);
    await expect(sky(page)).toHaveAttribute("aria-hidden", "true");
    const layer = await sky(page).evaluate(node => {
      const css = getComputedStyle(node);
      const box = node.getBoundingClientRect();
      return {
        position: css.position,
        behind: Number(css.zIndex) < 0,
        events: css.pointerEvents,
        covers: box.width >= innerWidth && box.height >= innerHeight,
      };
    });
    expect(layer).toEqual({ position: "fixed", behind: true, events: "none", covers: true });
    expect(problems, problems.join("\n")).toEqual([]);
  });

  test("is on the sign-in screen too", async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${process.env.E2E_PORT || "43210"}/login`);
    await expect(sky(page)).toHaveCount(1);
    await context.close();
  });

  test("has twinkling stars and falling streaks", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await openPage(page, "/", "Dashboard");
    const counts = await animations(page);
    expect(counts["twinkle:shown"]).toBeGreaterThanOrEqual(40);
    expect(counts["shootingStar:shown"]).toBeGreaterThanOrEqual(15);
  });

  test("holds still, with no streaks, when the person prefers reduced motion", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await openPage(page, "/", "Dashboard");
    // The streaks are hidden outright and the twinkling stops.
    expect(await animations(page)).toEqual({ "shootingStar:hidden": expect.any(Number) });
  });

  test("follows the theme: a dark sky behind a dark page, a pale one behind a light page", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "dark" });
    await openPage(page, "/", "Dashboard");
    expect(luminance(await averageColor(page, corner(page)))).toBeLessThan(0.15);

    await page.emulateMedia({ colorScheme: "light" });
    await page.evaluate(() => localStorage.removeItem("theme"));
    await page.reload();
    await expect(page.getByRole("heading", { level: 2, name: "Dashboard" })).toBeVisible();
    expect(luminance(await averageColor(page, corner(page)))).toBeGreaterThan(0.85);
  });

  test("switches with the Dark Mode button without a reload", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await openPage(page, "/", "Dashboard");
    const before = luminance(await averageColor(page, corner(page)));
    if ((page.viewportSize()?.width ?? 1280) < 768) {
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await page.locator("#mobile-menu").getByRole("button", { name: "Dark Mode" }).click();
      await page.mouse.click(370, 400);
    } else {
      await page.locator("aside").getByRole("button", { name: "Dark Mode" }).click();
    }
    await expect.poll(async () => luminance(await averageColor(page, corner(page)))).toBeLessThan(before - 0.5);
  });

  test("the streaks really move", async ({ browser }) => {
    const context = await browser.newContext({
      storageState: { cookies: [], origins: [] },
      viewport: { width: 1280, height: 800 },
      colorScheme: "dark",
      reducedMotion: "no-preference",
    });
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${process.env.E2E_PORT || "43210"}/login`);
    const openSpace = { x: 0, y: 0, width: 330, height: 800 };
    const first = await page.screenshot({ clip: openSpace });
    let changed = false;
    for (let attempt = 0; attempt < 12 && !changed; attempt += 1) {
      await page.waitForTimeout(400);
      changed = !(await page.screenshot({ clip: openSpace })).equals(first);
    }
    expect(changed).toBe(true);
    await context.close();
  });
});
