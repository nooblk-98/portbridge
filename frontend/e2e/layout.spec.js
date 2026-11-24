// @ts-check
const { test, expect } = require("@playwright/test");
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
      expect(problems).toEqual([]);
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
