// @ts-check
const { test, expect } = require("./fixtures");
const {
  isMobile,
  openPage,
  navigateTo,
  expectNoHorizontalScroll,
  watchForProblems,
} = require("./helpers");

const PAGES = [
  { path: "/", heading: "Dashboard", nav: "Dashboard" },
  { path: "/clients", heading: "Clients", nav: "Clients" },
  { path: "/routes", heading: "Route access", nav: "Routes" },
  { path: "/forwarding", heading: "Port Forwarding", nav: "Forwarding" },
];

test.describe("every page", () => {
  for (const { path, heading } of PAGES) {
    test(`${heading}: loads cleanly and never scrolls sideways`, async ({ page }) => {
      const problems = watchForProblems(page);
      await openPage(page, path, heading);
      await page.waitForLoadState("networkidle");
      await expectNoHorizontalScroll(page);
      expect(problems, problems.join("\n")).toEqual([]);
    });
  }
});

test.describe("navigation", () => {
  test("moves between all pages and keeps the address bar and title in step", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    for (const { path, heading, nav } of PAGES.slice(1)) {
      await navigateTo(page, nav);
      await expect(page.getByRole("heading", { level: 2, name: heading })).toBeVisible();
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page).toHaveTitle(new RegExp(nav));
    }
    await page.goBack();
    await expect(page.getByRole("heading", { level: 2, name: "Routes" }).or(
      page.getByRole("heading", { level: 2, name: "Route access" }),
    )).toBeVisible();
  });

  test("the current page is marked in the navigation", async ({ page }) => {
    await openPage(page, "/clients", "Clients");
    if (isMobile(page)) {
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await expect(page.locator("#mobile-menu").getByRole("link", { name: "Clients" })).toHaveAttribute(
        "aria-current",
        "page",
      );
    } else {
      await expect(page.locator("aside").getByRole("link", { name: "Clients" })).toHaveAttribute(
        "aria-current",
        "page",
      );
    }
  });
});

test.describe("static files", () => {
  test("are requested with the release number, so a caching proxy cannot serve stale ones", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    const addresses = await page.evaluate(() =>
      [...document.querySelectorAll('link[href^="/static/"], script[src^="/static/"], img[src^="/static/"]')].map(
        node => node.getAttribute("href") || node.getAttribute("src"),
      ),
    );
    expect(addresses.length).toBeGreaterThanOrEqual(8);
    for (const address of addresses) {
      expect(address, address).toMatch(/\?v=\d+\.\d+\.\d+(-[\w.]+)?$/);
      expect((await page.request.get(address)).status(), address).toBe(200);
    }
  });
});

test.describe("branding and decoration", () => {
  test("the sidebar logo is a plain circle, not a logo inside a tile", async ({ page }) => {
    test.skip((page.viewportSize()?.width ?? 1280) < 768, "the sidebar is desktop only");
    await openPage(page, "/", "Dashboard");
    const logo = page.locator("aside").getByRole("img", { name: "Port Bridge Logo" });
    await expect(logo).toBeVisible();
    const style = await logo.evaluate(node => {
      const css = getComputedStyle(node);
      return {
        radius: css.borderTopLeftRadius,
        padding: css.paddingTop,
        background: css.backgroundColor,
        shadow: css.boxShadow,
      };
    });
    // A circle (rounded at least to half its 40px size), with no padding, fill or shadow tile around it.
    expect(parseFloat(style.radius)).toBeGreaterThanOrEqual(20);
    expect({ padding: style.padding, background: style.background, shadow: style.shadow }).toEqual({
      padding: "0px",
      background: "rgba(0, 0, 0, 0)",
      shadow: "none",
    });
  });

  for (const scheme of ["light", "dark"]) {
    test(`the big icons behind the stat cards are clearly visible in ${scheme} mode`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme === "dark" ? "dark" : "light" });
      await openPage(page, "/", "Dashboard");
      for (const icon of ["group", "alt_route", "hub"]) {
        const tile = page.locator("main span.material-symbols-rounded", { hasText: new RegExp(`^${icon}$`) }).first();
        await expect(tile).toBeVisible();
        const opacity = await tile.evaluate(node => Number(getComputedStyle(/** @type {Element} */ (node.parentElement)).opacity));
        // They used to sit at 0.1, which was barely there.
        expect(opacity, `${icon} icon opacity`).toBeGreaterThanOrEqual(0.25);
      }
    });
  }
});

test.describe("footer", () => {
  test("there is exactly one footer, with the repository, version and author links", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    await expect(page.locator("footer")).toHaveCount(1);
    await expect(page.getByText("Made with")).toHaveCount(1);
    const footer = page.locator("footer");
    await expect(footer.getByRole("link", { name: "GitHub" })).toHaveAttribute(
      "href",
      "https://github.com/nooblk-98/portbridge",
    );
    await expect(footer.getByRole("link", { name: /^v\d/ })).toHaveAttribute("href", /\/releases$/);
    await expect(footer.getByRole("link", { name: "nooblk" })).toHaveAttribute(
      "href",
      "https://github.com/nooblk-98",
    );
    await expect(footer).toContainText("for the community");
  });

  test("the footer is not repeated in the sidebar or the menu drawer", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    await expect(page.locator("aside").getByText("Made with")).toHaveCount(0);
    await expect(page.locator("#mobile-menu").getByText("Made with")).toHaveCount(0);
  });

  test("the footer stays pinned to the bottom while the page scrolls", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    await page.waitForLoadState("networkidle");
    const bottomOffset = async () =>
      page.locator("footer").evaluate(node => Math.round(innerHeight - node.getBoundingClientRect().bottom));
    expect(await bottomOffset()).toBe(0);
    await page.locator("main").evaluate(node => node.scrollTo(0, node.scrollHeight));
    expect(await bottomOffset()).toBe(0);
    await expect(page.locator("footer")).toBeInViewport();
  });
});

test.describe("theme", () => {
  test("toggling switches between light and dark and survives a reload", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await openPage(page, "/", "Dashboard");
    const html = page.locator("html");
    await expect(html).not.toHaveClass(/\bdark\b/);

    if (isMobile(page)) await page.getByRole("button", { name: "Open navigation menu" }).click();
    const scope = isMobile(page) ? page.locator("#mobile-menu") : page.locator("aside");
    await scope.getByRole("button", { name: "Dark Mode" }).click();
    await expect(html).toHaveClass(/\bdark\b/);

    await page.reload();
    await expect(html).toHaveClass(/\bdark\b/);

    if (isMobile(page)) await page.getByRole("button", { name: "Open navigation menu" }).click();
    await scope.getByRole("button", { name: "Light Mode" }).click();
    await expect(html).not.toHaveClass(/\bdark\b/);
  });

  test("follows the system colour scheme when nothing is chosen", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "dark" });
    await openPage(page, "/", "Dashboard");
    await expect(page.locator("html")).toHaveClass(/\bdark\b/);
  });
});

test.describe("phone layout", () => {
  test.skip(({ viewport }) => (viewport?.width ?? 1280) >= 768, "phone only");

  test("shows a header with the menu button and no sidebar", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    await expect(page.getByRole("button", { name: "Open navigation menu" })).toBeVisible();
    await expect(page.locator("aside")).toBeHidden();
  });

  test("the drawer opens, lists every page and closes from the backdrop", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    const toggle = page.getByRole("button", { name: "Open navigation menu" });
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    const drawer = page.locator("#mobile-menu");
    for (const { nav } of PAGES) {
      await expect(drawer.getByRole("link", { name: nav })).toBeVisible();
    }
    await page.mouse.click(370, 400);
    await expect(drawer).toBeHidden();
  });
});

test.describe("desktop layout", () => {
  test.skip(({ viewport }) => (viewport?.width ?? 1280) < 768, "desktop only");

  test("shows the sidebar and no phone header", async ({ page }) => {
    await openPage(page, "/", "Dashboard");
    await expect(page.locator("aside")).toBeVisible();
    await expect(page.getByRole("button", { name: "Open navigation menu" })).toBeHidden();
  });
});
